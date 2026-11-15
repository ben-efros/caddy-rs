//! `caddy-rs setup`: the single-use activation endpoint (T-SETUP-002).
//!
//! `caddy-rs setup` (T-SETUP-001) mints a single-use token and prints activation URLs. This module
//! is the other half: the temporary activation layer that answers those URLs until enrollment
//! (T-SETUP-003) completes.
//!
//! # Protocol
//!
//! `GET`/`POST /_caddy-pm/activate?token=<32 lowercase hex chars>`:
//!
//! | outcome | status | body |
//! |---|---|---|
//! | token valid, first use | `200` | `{"status":"activated","auth_method":…,"enrollment":"pending"}` |
//! | token expired | `410 Gone` | `{"error":"token_expired"}` |
//! | token unknown or already used | `404 Not Found` | `{"error":"token_unknown"}` |
//! | `token` parameter missing | `400 Bad Request` | `{"error":"token_missing"}` |
//! | `token` not 32 lowercase hex chars | `400 Bad Request` | `{"error":"token_malformed"}` |
//! | any other path | `404 Not Found` | `{"error":"not_found"}` |
//! | any other method | `405 Method Not Allowed` | `{"error":"method_not_allowed"}`, `Allow: GET, POST` |
//!
//! The token is consumed by the *first* request that presents it, whatever the method, and it is
//! consumed before enrollment is reached, so a replay can never reach enrollment twice. Consuming is
//! one locked store operation, which is what makes "exactly once" true under concurrent requests
//! rather than only in a sequential test.
//!
//! Tokens are process-local (T-SETUP-005 moves them into `caddy-pm-rs` storage). The endpoint writes
//! no log lines and never echoes a token value in a response, so a token cannot leak through the
//! activation layer.
//!
//! # How it is served
//!
//! The handler is `http.handlers.caddy_pm_activation`, a caddy-rs handler module contributed to the
//! router through the same custom-handler factory the proxy crate uses. It is not in
//! [`caddy_rs_core::BUILTIN_MODULES`] on purpose: the token store lives in this process, so the
//! module only exists for the setup boot and is absent from a normal `caddy-rs run` generation.
//!
//! The generated Caddyfile (T-SETUP-001) stays the operator-visible description of the temporary
//! layer; the JSON this module serves is built in [`activation_config`] and shares
//! [`crate::setup::ACTIVATION_PATH`] with it, so the two cannot drift apart.
//!
//! Enrollment itself is T-SETUP-003 and is absent from this build, so the successful response names
//! the enrollment state instead of claiming credentials were registered.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use caddy_rs_core::{
    AdminConfig, Apps, AutoHttps, Config, GenerationStore, HttpApp, HttpServer, Route,
};
use caddy_rs_http::types::{Handler, Outcome, Request, Response, Result as HttpResult};
use caddy_rs_http::{CustomHandlerFactory, HandlerBuildContext, RouterBuilder};
use caddy_rs_server::ServerRuntime;
use serde_json::{Map, Value};

use crate::setup::{AuthMethod, TokenError, TokenStore, ACTIVATION_PATH};

/// The handler module name used in JSON (`{"handler": "caddy_pm_activation"}`).
pub const ACTIVATION_HANDLER: &str = "caddy_pm_activation";

/// The module id of the activation handler.
pub const ACTIVATION_HANDLER_ID: &str = "http.handlers.caddy_pm_activation";

/// Registry entry for the activation handler.
///
/// The module is registered at boot, not in [`caddy_rs_core::BUILTIN_MODULES`]: the token store
/// lives in this process, so the handler exists only for the setup boot and a normal
/// `caddy-rs run` generation must reject it as an unknown module instead of accepting a
/// configuration it cannot serve.
pub fn activation_module() -> caddy_rs_core::Module {
    caddy_rs_core::Module::new(
        ACTIVATION_HANDLER_ID,
        ACTIVATION_HANDLER,
        caddy_rs_core::ModuleKind::HttpHandler,
        "caddy-rs setup single-use activation endpoint (T-SETUP-002)",
    )
}

/// A module registry with the activation handler registered on top of `base`.
pub fn registry_with_activation(
    mut base: caddy_rs_core::ModuleRegistry,
) -> Result<caddy_rs_core::ModuleRegistry> {
    base.register(activation_module())
        .context("cannot register the activation handler module")?;
    Ok(base)
}

/// Caddy's `buildHTTPServer` read-header timeout, as `caddy-rs respond` uses it.
const READ_HEADER_TIMEOUT: &str = "10s";
/// Caddy's `buildHTTPServer` idle timeout.
const IDLE_TIMEOUT: &str = "30s";
/// Caddy's `buildHTTPServer` maximum header size.
const MAX_HEADER_BYTES: u64 = 10 * 1024;

/// An activation outcome, rendered as the HTTP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// The token was valid and has now been consumed.
    Activated,
    /// The token was well-formed but its TTL elapsed (the token is discarded).
    Expired,
    /// The token is not in the store: never minted, or already consumed.
    Unknown,
    /// No `token` query parameter.
    MissingToken,
    /// `token` is not 32 lowercase hex characters.
    MalformedToken,
    /// The path is not [`ACTIVATION_PATH`].
    NotFound,
    /// The method is neither `GET` nor `POST`.
    MethodNotAllowed,
}

impl ActivationOutcome {
    /// HTTP status for the outcome.
    pub fn status(self) -> u16 {
        match self {
            Self::Activated => 200,
            Self::Expired => 410,
            Self::Unknown | Self::NotFound => 404,
            Self::MissingToken | Self::MalformedToken => 400,
            Self::MethodNotAllowed => 405,
        }
    }

    /// Stable machine-readable error code, or `None` for a successful activation.
    pub fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Activated => None,
            Self::Expired => Some("token_expired"),
            Self::Unknown => Some("token_unknown"),
            Self::MissingToken => Some("token_missing"),
            Self::MalformedToken => Some("token_malformed"),
            Self::NotFound => Some("not_found"),
            Self::MethodNotAllowed => Some("method_not_allowed"),
        }
    }

    /// Response headers for the outcome.
    pub fn headers(self) -> Vec<(&'static str, &'static str)> {
        let mut headers = vec![("content-type", "application/json")];
        if self == Self::MethodNotAllowed {
            headers.push(("allow", "GET, POST"));
        }
        headers
    }

    /// JSON body for the outcome. Never contains the presented token.
    pub fn body(self, auth_method: AuthMethod) -> String {
        let mut object = Map::new();
        match self.error_code() {
            None => {
                object.insert("status".into(), Value::String("activated".into()));
                object.insert(
                    "auth_method".into(),
                    Value::String(auth_method.as_str().to_string()),
                );
                // Enrollment is T-SETUP-003; naming the state keeps the response honest instead of
                // claiming credentials exist.
                object.insert("enrollment".into(), Value::String("pending".into()));
            }
            Some(code) => {
                object.insert("error".into(), Value::String(code.to_string()));
            }
        }
        Value::Object(object).to_string()
    }
}

/// Whether a token has the documented shape: exactly 32 lowercase hex characters.
pub fn is_well_formed_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Split a request target into `(path, query)`.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// Value of the `token` query parameter, if present (first occurrence wins, like Go's `Query()`).
fn query_token(query: &str) -> Option<&str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == "token").then_some(value)
    })
}

/// The activation endpoint: one single-use token store plus the enrollment method.
///
/// The store is behind a `Mutex` because requests are served concurrently.
#[derive(Debug)]
pub struct ActivationService {
    tokens: Mutex<TokenStore>,
    auth_method: AuthMethod,
}

impl ActivationService {
    /// A service that accepts the tokens in `tokens`.
    pub fn new(tokens: TokenStore, auth_method: AuthMethod) -> Self {
        Self {
            tokens: Mutex::new(tokens),
            auth_method,
        }
    }

    /// Handle one request: `(method, request_target)` -> outcome.
    pub fn handle(&self, method: &str, target: &str) -> ActivationOutcome {
        let (path, query) = split_target(target);
        if path != ACTIVATION_PATH {
            return ActivationOutcome::NotFound;
        }
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("POST") {
            return ActivationOutcome::MethodNotAllowed;
        }
        let Some(token) = query_token(query) else {
            return ActivationOutcome::MissingToken;
        };
        if !is_well_formed_token(token) {
            return ActivationOutcome::MalformedToken;
        }
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match tokens.consume(token, std::time::SystemTime::now()) {
            Ok(()) => ActivationOutcome::Activated,
            Err(TokenError::Expired) => ActivationOutcome::Expired,
            Err(TokenError::Unknown) => ActivationOutcome::Unknown,
        }
    }

    /// The enrollment method announced to the browser.
    pub fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }
}

/// The `caddy_pm_activation` HTTP handler: serves [`ActivationService`] over the router.
pub struct ActivationHandler {
    service: Arc<ActivationService>,
}

impl ActivationHandler {
    /// Wrap a service.
    pub fn new(service: Arc<ActivationService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Handler for ActivationHandler {
    fn name(&self) -> &'static str {
        ACTIVATION_HANDLER
    }

    async fn handle(&self, request: Request) -> HttpResult<Outcome> {
        let method = request.method.as_str().to_string();
        let target = request
            .uri
            .path_and_query()
            .map(|path| path.as_str().to_string())
            .unwrap_or_else(|| request.uri.path().to_string());
        let outcome = self.service.handle(&method, &target);
        let mut headers = http::HeaderMap::new();
        for (name, value) in outcome.headers() {
            // `HeaderName` is lowercase by construction (`HeaderName::from_static` panics on
            // anything else), so the response header table must be spelled in lowercase.
            let name = http::HeaderName::from_static(name);
            let value = http::HeaderValue::from_static(value);
            headers.insert(name, value);
        }
        let status = http::StatusCode::from_u16(outcome.status()).unwrap_or(http::StatusCode::OK);
        Ok(Outcome::Respond(Response {
            status,
            headers,
            body: bytes::Bytes::from(outcome.body(self.service.auth_method())),
        }))
    }
}

/// A custom-handler factory that builds [`ActivationHandler`] for `caddy_pm_activation` objects.
pub fn handler_factory(service: Arc<ActivationService>) -> CustomHandlerFactory {
    Arc::new(
        move |value: &Value, _path: &str, _context: &HandlerBuildContext| {
            if value.get("handler").and_then(Value::as_str) == Some(ACTIVATION_HANDLER) {
                Ok(Some(Arc::new(ActivationHandler::new(Arc::clone(&service)))
                    as caddy_rs_http::types::SharedHandler))
            } else {
                Ok(None)
            }
        },
    )
}

/// The HTTP app that serves the activation endpoint on `listen`.
pub fn activation_config(listen: &str) -> Config {
    let mut handler = Map::new();
    handler.insert("handler".into(), Value::String(ACTIVATION_HANDLER.into()));
    let route = Route {
        handle: vec![Value::Object(handler)],
        ..Default::default()
    };
    let mut server = HttpServer {
        listen: vec![listen.to_string()],
        routes: vec![route],
        automatic_https: Some(AutoHttps {
            disable_redirects: true,
            ..Default::default()
        }),
        idle_timeout: Some(Value::String(IDLE_TIMEOUT.to_string())),
        ..Default::default()
    };
    server.extra.insert(
        "read_header_timeout".into(),
        Value::String(READ_HEADER_TIMEOUT.to_string()),
    );
    server
        .extra
        .insert("max_header_bytes".into(), Value::from(MAX_HEADER_BYTES));

    let mut servers = BTreeMap::new();
    servers.insert("activation".to_string(), server);
    let mut admin_extra = BTreeMap::new();
    admin_extra.insert(
        "config".to_string(),
        serde_json::json!({ "persist": false }),
    );

    Config {
        admin: Some(AdminConfig {
            disabled: true,
            extra: admin_extra,
            ..Default::default()
        }),
        apps: Some(Apps {
            http: Some(HttpApp {
                servers,
                // The activation layer is cleartext HTTP for now (DIV-0151). Port 443 is the
                // HTTPS port, so a listener there would be treated as a TLS listener with no
                // certificate; `https_port: 0` is Caddy's "no HTTPS port" spelling (automatic
                // HTTPS is off for this app anyway) and keeps the temporary endpoint serving
                // plain HTTP on whichever port the activation URL names.
                https_port: Some(0),
                ..Default::default()
            }),
            tls: None,
            pki: None,
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    }
}

/// Boot the activation listener on `listen` with an explicit module registry and signal source.
///
/// `listen` is a cleartext `host:port`. The printed activation URLs use `https://`; terminating TLS
/// for the temporary layer belongs to the generation-scoped `caddy-pm-rs` service (T-SETUP-004,
/// ADR-006), which this build does not have. Binding plain HTTP keeps the endpoint reachable for
/// the boot check instead of pretending TLS exists; DIV-0151 records the difference.
///
/// The registry and the shutdown channels are parameters so the integration test can boot the real
/// listener without the binary's own module table, which is private to `main.rs`.
pub async fn serve_with(
    listen: &str,
    service: Arc<ActivationService>,
    registry: caddy_rs_core::ModuleRegistry,
    shutdown: tokio::sync::watch::Receiver<bool>,
    force: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let config = activation_config(listen);
    let store = Arc::new(GenerationStore::new(Arc::new(registry_with_activation(
        registry,
    )?)));
    store
        .load(config)
        .context("cannot activate the setup activation layer")?;
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_extension_handler_factory(handler_factory(service))
        .without_socket_activation();
    let status = runtime
        .apply()
        .await
        .context("cannot start the setup activation layer")?;
    let bound = status.listener_address(listen).ok_or_else(|| {
        anyhow::anyhow!("activation listener `{listen}` was configured but did not bind")
    })?;
    // The bound address is printed so the boot check can reach the endpoint; the token itself is
    // never printed here (the caller prints it once, on the activation URL).
    eprintln!("caddy-rs setup: activation endpoint listening on http://{bound}{ACTIVATION_PATH}");

    runtime
        .run_with_force(shutdown, force)
        .await
        .context("activation layer failed")?;
    Ok(())
}

/// Router builder wired with the activation handler factory.
///
/// The activation app is served by [`serve_with`], which builds its router from this builder.
pub fn router_builder(service: Arc<ActivationService>) -> RouterBuilder {
    RouterBuilder::new().with_custom_handler(handler_factory(service))
}
