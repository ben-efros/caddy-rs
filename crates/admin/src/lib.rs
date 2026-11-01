//! Caddy-compatible admin API (logic layer).
//!
//! The admin API is an architectural feature, not a convenience: it is how a running process
//! takes a new configuration without restarting. This crate implements the request semantics
//! against [`caddy_rs_core::GenerationStore`] and is transport-agnostic so it can be unit-tested;
//! `caddy-rs-server` binds it to a hyper listener.
//!
//! Implemented endpoints (Caddy v2.11.7 admin API surface):
//!
//! | Endpoint | Behaviour |
//! |---|---|
//! | `GET /config/` | Current configuration as JSON (`{}` when no generation is active) |
//! | `GET /config/<path>` | JSON traversal by object key or array index |
//! | `POST`/`PUT`/`PATCH`/`DELETE /config/<path>` | Partial configuration update with validation and rollback |
//! | `GET /id/<id>` | Object (route) addressed by its `@id`, including nested subroutes |
//! | `POST`/`PUT`/`PATCH`/`DELETE /id/<id>[/<path>]` | Partial update addressed by `@id` |
//! | `POST /load` | Validate, provision, and atomically activate a configuration |
//! | `POST /stop` | Deactivate the running configuration |
//! | `GET /metrics` | Prometheus text format (v0.0.4) rendered from the shared [`MetricsRegistry`]; empty until the runtime populates it |
//!
//! Partial updates follow upstream Caddy's semantics exactly (see `config_path`):
//!
//! - `PUT` creates an object key (409 if it exists) or inserts an array element at an index
//!   (`len` appends).
//! - `PATCH` replaces an existing object key (404 if missing) or array element.
//! - `POST` appends to an array (the index segment of a terminal array path is ignored, as in
//!   Caddy) and sets object keys; a trailing `...` expands an array payload into the destination
//!   array.
//! - `DELETE` removes an object key/array element (404 if missing).
//!
//! ## Observability primitives
//!
//! [`metrics`] implements a hand-written Prometheus text-format registry (counters, gauges,
//! histograms, labelled series, deterministic rendering) and a typed layer for the Caddy HTTP
//! series plus caddy-rs proxy/certificate extensions. `GET /metrics` renders the registry, and
//! [`AdminApi::metrics`] hands the same registry to the server runtime for population.
//!
//! [`access_log`] models Caddy's structured access-log entry (request/TLS/upstream fields),
//! with field selection, sampling and redaction primitives. Wiring the model to a log sink is a
//! server-runtime follow-up.
//!
//! ## Partial updates
//!
//! The resulting *full* configuration is decoded, `@id`-indexed (duplicate ids are rejected with
//! both locations), validated, and only then swapped in atomically. A rejected update leaves the
//! previous generation active; the store's compare-before-swap makes rollback automatic.
//!
//! Documented simplifications:
//!
//! - Malformed bodies and traversal errors return `400` with a located message. Upstream Caddy
//!   only wraps *some* errors in `APIError`, so several equivalent failures surface as `500`.
//! - `If-Match` preconditions, `Cache-Control: must-revalidate`, `ETag` generation, and the
//!   "config unchanged" short-circuit are not implemented; every accepted update yields a new
//!   generation.
//! - `POST /config/` replaces the whole configuration; `DELETE /config/` unloads it (Caddy
//!   reaches the same state through `run(nil)` via its `rawCfg` wrapper).
//! - Origin enforcement is evaluated from the active generation on each request; the server crate
//!   may instead pass the startup policy with [`AdminApi::with_origin_policy`].
//! - Paths are used as the transport transmits them; percent-encoded segments are not decoded
//!   (Caddy's `net/url` decodes `URL.Path` before dispatch). The server crate passes the raw
//!   request path, so `@id` values and object keys containing reserved characters need literal
//!   segments.
//! - `GET /config/<missing>` reports a located `404`; Caddy renders a missing path as `null` with
//!   `200`. `GET /id/<id>` returns `404` for unknown ids as required by the admin contract.
//! - Origin policy derives implicit origins from a non-empty `admin.origins`; the shared core
//!   model cannot distinguish `origins: null` (derive) from `origins: []` (allow none), so an
//!   explicit empty list derives the defaults instead of blocking the endpoint.
//! - Metrics and access logging are crate-level primitives (T-ADMIN-020/T-ADMIN-021): the
//!   registry is exposed for the server runtime to populate, and the access-log record model is
//!   not yet wired to a sink. `/metrics` renders whatever the registry currently holds, which is
//!   empty until the runtime records something.

#![forbid(unsafe_code)]

pub mod access_log;
mod config_path;
pub mod metrics;
mod origin;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{drain, Config, GenerationStore, LifecycleState};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

pub use access_log::{
    AccessLogConfig, AccessLogEntry, AccessLogError, AccessLogField, AccessLogRequest,
    AccessLogSampler, AccessLogTls, AccessLogUpstream, HeaderRedaction, HeaderTarget, LogLevel,
    RedactionPolicy, SamplingConfig,
};
pub use metrics::{
    HttpMetrics, MetricsError, MetricsRegistry, ProxyObservation, RequestObservation,
    METRICS_CONTENT_TYPE,
};
pub use origin::{OriginPolicy, OriginViolation};

use config_path::{index_config, navigate, Mutation};

/// An admin API request, independent of the transport.
#[derive(Debug, Clone)]
pub struct AdminRequest {
    /// HTTP method.
    pub method: Method,
    /// Request path, including query if present.
    pub path: String,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body.
    pub body: Bytes,
}

/// An admin API response.
#[derive(Debug, Clone)]
pub struct AdminResponse {
    /// Status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body.
    pub body: Bytes,
}

impl AdminResponse {
    /// Empty response with a status.
    pub fn empty(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    /// Plain-text response.
    pub fn text(status: StatusCode, body: impl Into<Bytes>) -> Self {
        let mut response = Self::empty(status);
        response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response.body = body.into();
        response
    }

    /// JSON response.
    pub fn json(status: StatusCode, value: &Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|error| {
            format!("{{\"error\":\"serialization: {error}\"}}").into_bytes()
        });
        let mut response = Self::empty(status);
        response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response.body = Bytes::from(body);
        response
    }

    /// Caddy-compatible `APIError` body: `{"error":"<message>"}` with JSON content type.
    pub fn api_error(status: StatusCode, message: impl AsRef<str>) -> Self {
        Self::json(status, &json!({ "error": message.as_ref() }))
    }
}

/// Admin API logic bound to a generation store.
#[derive(Debug, Clone)]
pub struct AdminApi {
    store: Arc<GenerationStore>,
    drain_timeout: Duration,
    reload_notify: Option<Arc<tokio::sync::Notify>>,
    origin_policy: Option<OriginPolicy>,
    metrics: MetricsRegistry,
}

impl AdminApi {
    /// Create an admin API for a store.
    pub fn new(store: Arc<GenerationStore>) -> Self {
        Self {
            store,
            drain_timeout: Duration::from_secs(30),
            reload_notify: None,
            origin_policy: None,
            metrics: MetricsRegistry::new(),
        }
    }

    /// Use a pre-populated metrics registry instead of a fresh one.
    ///
    /// The server runtime builds its instrumentation from this same registry (see
    /// [`AdminApi::metrics`]), so `GET /metrics` renders exactly the series the runtime records.
    pub fn with_metrics(mut self, metrics: MetricsRegistry) -> Self {
        self.metrics = metrics;
        self
    }

    /// A cheap handle to the metrics registry for the server runtime to populate.
    pub fn metrics(&self) -> MetricsRegistry {
        self.metrics.clone()
    }

    /// Wake the runtime supervisor immediately after a successful load/stop instead of waiting
    /// for its poll interval.
    pub fn with_reload_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.reload_notify = Some(notify);
        self
    }

    /// Fix the origin policy at construction time.
    ///
    /// A real admin listener applies `admin.enforce_origin`/`admin.origins` from the configuration
    /// that started it. Without this override the policy is derived from the active generation on
    /// every request, which is convenient for tests and for transports that can restart the admin
    /// listener with a new configuration.
    pub fn with_origin_policy(mut self, policy: OriginPolicy) -> Self {
        self.origin_policy = Some(policy);
        self
    }

    /// Override the graceful-drain timeout for replaced generations.
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// The generation store behind the API.
    pub fn store(&self) -> &Arc<GenerationStore> {
        &self.store
    }

    fn notify_reload(&self) {
        if let Some(notify) = &self.reload_notify {
            notify.notify_one();
        }
    }

    /// The origin policy for this request: an explicit startup policy if configured, otherwise the
    /// active generation's `admin` block (Caddy defaults when there is no generation).
    fn origin_policy(&self) -> OriginPolicy {
        if let Some(policy) = &self.origin_policy {
            return policy.clone();
        }
        let admin = self
            .store
            .current()
            .and_then(|generation| generation.config().admin.clone());
        OriginPolicy::from_admin(admin.as_ref())
    }

    /// The active configuration as JSON, or `Null` when no generation is active.
    fn current_config_value(&self) -> Value {
        self.store
            .current()
            .and_then(|generation| generation.config().to_value().ok())
            .unwrap_or(Value::Null)
    }

    /// Handle one request.
    pub async fn handle(&self, request: AdminRequest) -> AdminResponse {
        let (path, _query) = match request.path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.path.as_str(), None),
        };

        let origin = match self.origin_policy().check(&request.headers) {
            Ok(origin) => origin,
            Err(violation) => return AdminResponse::api_error(violation.status, violation.message),
        };

        let mut response = self.dispatch(path, &request).await;

        // Caddy echoes the accepted origin for browser clients.
        if let Some(origin) = origin {
            if let Ok(value) = HeaderValue::from_str(&origin) {
                response
                    .headers
                    .insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            }
        }
        response
    }

    async fn dispatch(&self, path: &str, request: &AdminRequest) -> AdminResponse {
        let method = request.method.as_str();

        if path == "/config/" || path == "/config" {
            if method != "GET" {
                return self.handle_config_update(path, request);
            }
            let config = self
                .store
                .current()
                .and_then(|generation| generation.config().to_value().ok())
                .unwrap_or_else(|| json!({}));
            return AdminResponse::json(StatusCode::OK, &config);
        }

        if let Some(pointer) = path.strip_prefix("/config/") {
            if method != "GET" {
                return self.handle_config_update(path, request);
            }
            let current = self.current_config_value();
            let parts = config_path::split_path(pointer);
            return match navigate(&current, &parts) {
                Some(value) => AdminResponse::json(StatusCode::OK, value),
                None => AdminResponse::text(
                    StatusCode::NOT_FOUND,
                    format!("config path `{pointer}` not found"),
                ),
            };
        }

        if let Some(rest) = path.strip_prefix("/id/") {
            return self.handle_id(rest, request);
        }

        match path {
            "/id" | "/id/" => AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                "request path is missing object ID",
            ),
            "/load" => {
                if method != "POST" {
                    return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let config = match Config::from_slice(&request.body) {
                    Ok(config) => config,
                    Err(error) => {
                        return AdminResponse::text(
                            StatusCode::BAD_REQUEST,
                            format!("invalid config JSON: {error}"),
                        )
                    }
                };
                // Caddy indexes every `@id` before running a config and rejects duplicates with
                // both locations (this also covers non-route objects the core validator does not
                // model).
                match config
                    .to_value()
                    .map_err(|error| error.to_string())
                    .and_then(|value| index_config(&value))
                {
                    Ok(_) => {}
                    Err(message) => {
                        return AdminResponse::api_error(
                            StatusCode::BAD_REQUEST,
                            format!("indexing config: {message}"),
                        )
                    }
                }
                self.commit(config)
            }
            "/stop" => {
                if method != "POST" {
                    return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                self.unload()
            }
            "/metrics" => {
                if method != "GET" {
                    return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let mut response = AdminResponse::text(StatusCode::OK, self.metrics.render());
                response.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(METRICS_CONTENT_TYPE),
                );
                response
            }
            "/healthz" => AdminResponse::json(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "active_generation": self.store.current().map(|generation| generation.id()),
                    "lifecycle": self.store.current().map(|generation| generation.state().as_str()),
                }),
            ),
            _ => AdminResponse::text(
                StatusCode::NOT_FOUND,
                format!("admin endpoint `{path}` is not implemented"),
            ),
        }
    }

    /// Apply a `POST`/`PUT`/`PATCH`/`DELETE` mutation to the active config path and commit the
    /// resulting full configuration, rolling back on any decode, index, or validation error.
    fn handle_config_update(&self, path: &str, request: &AdminRequest) -> AdminResponse {
        let Some(mutation) = Mutation::from_method(request.method.as_str()) else {
            return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
        };

        if mutation != Mutation::Delete {
            let content_type = request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if !content_type.contains("/json") {
                return AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "unacceptable content-type: {content_type}; 'application/json' required"
                    ),
                );
            }
        }

        let body = if request.body.is_empty() {
            None
        } else {
            match serde_json::from_slice::<Value>(&request.body) {
                Ok(value) => Some(value),
                Err(error) => {
                    return AdminResponse::api_error(
                        StatusCode::BAD_REQUEST,
                        format!("decoding request body: {error}"),
                    )
                }
            }
        };

        let mut parts = config_path::split_path(path);
        let ellipses = parts.last().is_some_and(|part| *part == "...");
        if ellipses {
            parts.pop();
        }

        // Reproduce Caddy's `rawCfg` wrapper so root-level operations have identical semantics:
        // the active document lives under the `config` key.
        let mut wrapper = json!({ "config": self.current_config_value() });
        if let Err(error) =
            config_path::mutate(&mut wrapper, mutation, &parts, ellipses, body.as_ref())
        {
            return AdminResponse::api_error(error.status, error.message);
        }

        let updated = wrapper.get("config").cloned().unwrap_or(Value::Null);
        if updated.is_null() {
            // `DELETE /config/` removes the wrapper key; Caddy then runs a nil config, which
            // stops all apps. Model that as unloading the generation.
            return self.unload();
        }

        if let Err(message) = index_config(&updated) {
            return AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                format!("indexing config: {message}"),
            );
        }

        let config = match Config::from_value(updated) {
            Ok(config) => config,
            Err(error) => {
                return AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    format!("loading new config: {error}"),
                )
            }
        };

        self.commit(config)
    }

    /// Resolve `/id/<id>[/<path>]` against the indexed active configuration and dispatch either a
    /// read or a partial update on the expanded `/config/...` path.
    fn handle_id(&self, rest: &str, request: &AdminRequest) -> AdminResponse {
        let mut segments = rest.split('/');
        let id = segments.next().unwrap_or("");
        if id.is_empty() {
            return AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                "request path is missing object ID",
            );
        }
        // Caddy rebuilds the path with `path.Join`, which collapses empty and `.` segments.
        let trailing: Vec<&str> = segments
            .filter(|segment| !segment.is_empty() && *segment != ".")
            .collect();

        let current = self.current_config_value();
        let index = match index_config(&current) {
            Ok(index) => index,
            Err(message) => {
                return AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    format!("indexing config: {message}"),
                )
            }
        };
        let Some(expanded) = index.get(id) else {
            return AdminResponse::api_error(
                StatusCode::NOT_FOUND,
                format!("unknown object ID '{id}'"),
            );
        };

        let mut parts: Vec<&str> = expanded.iter().map(String::as_str).collect();
        parts.extend(trailing.iter().copied());

        if request.method == Method::GET {
            if let Some(value) = navigate(&current, &parts) {
                return AdminResponse::json(StatusCode::OK, value);
            }
            return AdminResponse::text(
                StatusCode::NOT_FOUND,
                format!("config path `{rest}` not found"),
            );
        }

        let expanded_path = if parts.is_empty() {
            "/config/".to_string()
        } else {
            format!("/config/{}", parts.join("/"))
        };
        let mut rewritten = request.clone();
        rewritten.path = expanded_path.clone();
        self.handle_config_update(&expanded_path, &rewritten)
    }

    /// Atomically activate a validated configuration and drain the replaced generation.
    fn commit(&self, config: Config) -> AdminResponse {
        match self.store.load(config) {
            Ok(loaded) => {
                if let Some(replaced) = loaded.replaced {
                    let timeout = self.drain_timeout;
                    tokio::spawn(async move {
                        let _ = drain(&replaced, timeout).await;
                    });
                }
                self.notify_reload();
                AdminResponse::empty(StatusCode::OK)
            }
            Err(error) => AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                format!("loading new config: {error}"),
            ),
        }
    }

    /// Deactivate the running configuration (shared by `POST /stop` and `DELETE /config/`).
    fn unload(&self) -> AdminResponse {
        if let Some(generation) = self.store.stop() {
            let timeout = self.drain_timeout;
            tokio::spawn(async move {
                let _ = drain(&generation, timeout).await;
            });
        }
        self.notify_reload();
        AdminResponse::empty(StatusCode::OK)
    }
}

/// Expected lifecycle state transitions observed through the admin API; used by tests and the
/// server's readiness probe.
pub fn is_running(store: &GenerationStore) -> bool {
    store
        .current()
        .map(|generation| matches!(generation.state(), LifecycleState::Active))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> AdminApi {
        AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
    }

    fn request(method: &str, path: &str, body: &str) -> AdminRequest {
        AdminRequest {
            method: method.parse().unwrap(),
            path: path.to_string(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
        }
    }

    /// A request with the `Content-Type: application/json` header Caddy requires for updates.
    fn json_request(method: &str, path: &str, body: impl ToString) -> AdminRequest {
        let mut request = request(method, path, &body.to_string());
        request.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request
    }

    fn with_origin(mut request: AdminRequest, origin: &str) -> AdminRequest {
        request
            .headers
            .insert(http::header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        request
    }

    fn valid_config() -> String {
        serde_json::json!({
            "admin": {"listen": "localhost:2019"},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        })
        .to_string()
    }

    fn config_with_routes(routes: Value) -> String {
        serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": routes,
            }}}}
        })
        .to_string()
    }

    async fn load(admin: &AdminApi, config: &str) -> AdminResponse {
        admin.handle(request("POST", "/load", config)).await
    }

    async fn get_config(admin: &AdminApi) -> Value {
        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        serde_json::from_slice(&response.body).unwrap()
    }

    fn body_string(response: &AdminResponse) -> String {
        String::from_utf8_lossy(&response.body).into_owned()
    }

    #[tokio::test]
    async fn load_then_read_config_and_paths() {
        let admin = admin();
        let response = load(&admin, &valid_config()).await;
        assert_eq!(response.status, StatusCode::OK);

        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["listen"][0],
            ":8080"
        );

        let response = admin
            .handle(request(
                "GET",
                "/config/apps/http/servers/srv0/listen/0",
                "",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!(":8080")
        );

        let response = admin
            .handle(request("GET", "/config/apps/missing", ""))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_and_previous_stays_active() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let invalid = serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "nope"}]}]
            }}}}
        });
        let response = admin
            .handle(request("POST", "/load", &invalid.to_string()))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("nope"));
        assert!(is_running(admin.store()));
    }

    #[tokio::test]
    async fn stop_deactivates_the_generation() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let response = admin.handle(request("POST", "/stop", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(!is_running(admin.store()));
        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"{}"));
    }

    #[tokio::test]
    async fn method_and_unknown_endpoint_errors() {
        let admin = admin();
        assert_eq!(
            admin.handle(request("GET", "/load", "")).await.status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            admin.handle(request("GET", "/nope", "")).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            admin.handle(request("GET", "/metrics", "")).await.status,
            StatusCode::OK
        );
        assert_eq!(
            admin.handle(request("POST", "/metrics", "")).await.status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // Caddy's route is `/config/`; the bare path is accepted for compatibility with the
        // previous caddy-rs behaviour.
        assert_eq!(
            admin.handle(request("GET", "/config", "")).await.status,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn patch_replaces_only_the_targeted_subtree() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        let replacement = json!({
            "handle": [{"handler": "static_response", "body": "patched"}]
        });
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/routes/0",
                &replacement,
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );

        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
            "patched"
        );
        // Untouched siblings survive.
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["listen"][0],
            ":8080"
        );
        assert_eq!(admin.store().current().unwrap().id(), 2);
    }

    #[tokio::test]
    async fn patch_terminal_object_key_inside_a_handler() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/routes/0/handle/0/body",
                json!("direct"),
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
            "direct"
        );
    }

    #[tokio::test]
    async fn put_create_conflict_patch_missing_and_delete() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        let server = json!({"listen": [":8081"], "routes": []});
        let response = admin
            .handle(json_request(
                "PUT",
                "/config/apps/http/servers/srv1",
                &server,
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv1"]["listen"][0],
            ":8081"
        );

        // PUT on an existing key conflicts.
        let response = admin
            .handle(json_request(
                "PUT",
                "/config/apps/http/servers/srv1",
                &server,
            ))
            .await;
        assert_eq!(response.status, StatusCode::CONFLICT);
        assert!(body_string(&response).contains("key already exists"));

        // PATCH requires an existing key.
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/does-not-exist",
                json!({}),
            ))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        let response = admin
            .handle(request("DELETE", "/config/apps/http/servers/srv1", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        let config = get_config(&admin).await;
        assert!(config["apps"]["http"]["servers"].get("srv1").is_none());

        // DELETE on a missing key is 404.
        let response = admin
            .handle(request("DELETE", "/config/apps/http/servers/srv1", ""))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_creates_missing_parent_objects() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let response = admin
            .handle(json_request(
                "PUT",
                "/config/apps/http/servers/srv0/routes/0/handle/0/headers/response/set/X-Test",
                json!(["ok"]),
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["headers"]
                ["response"]["set"]["X-Test"][0],
            "ok"
        );
    }

    #[tokio::test]
    async fn array_mutation_semantics() {
        let admin = admin();
        load(
            &admin,
            &config_with_routes(json!([
                {"@id": "a", "handle": [{"handler": "static_response", "body": "a"}]}
            ])),
        )
        .await;

        // POST on the array property appends an element.
        let route_b = json!({"@id": "b", "handle": [{"handler": "static_response", "body": "b"}]});
        let response = admin
            .handle(json_request(
                "POST",
                "/config/apps/http/servers/srv0/routes",
                &route_b,
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["routes"][1]["@id"],
            "b"
        );

        // POST with an index segment still appends (Caddy ignores the index for POST).
        let response = admin
            .handle(json_request(
                "POST",
                "/config/apps/http/servers/srv0/routes/0",
                &route_b,
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "duplicate id");
        assert!(body_string(&response).contains("duplicate ID 'b'"));

        // PUT inserts at the index.
        let route_c = json!({"@id": "c", "handle": [{"handler": "static_response", "body": "c"}]});
        let response = admin
            .handle(json_request(
                "PUT",
                "/config/apps/http/servers/srv0/routes/0",
                &route_c,
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        let ids: Vec<&str> = config["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["@id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["c", "a", "b"]);

        // DELETE removes the element at the index.
        let response = admin
            .handle(request(
                "DELETE",
                "/config/apps/http/servers/srv0/routes/1",
                "",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        let config = get_config(&admin).await;
        let ids: Vec<&str> = config["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["@id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["c", "b"]);

        // `...` expands every element of the array payload.
        let response = admin
            .handle(json_request(
                "POST",
                "/config/apps/http/servers/srv0/routes/...",
                json!([
                    {"@id": "d", "handle": [{"handler": "static_response"}]},
                    {"@id": "e", "handle": [{"handler": "static_response"}]}
                ]),
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        let ids: Vec<&str> = config["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["@id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["c", "b", "d", "e"]);
    }

    #[tokio::test]
    async fn invalid_partial_update_rolls_back_and_keeps_the_previous_generation() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let generation_before = admin.store().current().unwrap().id();
        let config_before = get_config(&admin).await;

        // Unknown handler module: the resulting full config fails validation.
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/routes/0/handle/0",
                json!({"handler": "definitely_not_a_module"}),
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("definitely_not_a_module"));

        // Removing the listen address also fails validation.
        let response = admin
            .handle(request(
                "DELETE",
                "/config/apps/http/servers/srv0/listen",
                "",
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);

        // Rollback: same generation, byte-identical configuration, still serving.
        assert_eq!(admin.store().current().unwrap().id(), generation_before);
        assert_eq!(get_config(&admin).await, config_before);
        assert!(is_running(admin.store()));
    }

    #[tokio::test]
    async fn update_rejects_bad_content_type_body_and_indexes() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        // Caddy requires application/json for mutating methods.
        let response = admin
            .handle(request(
                "PUT",
                "/config/apps/http/servers/srv1",
                r#"{"listen": [":8081"]}"#,
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("unacceptable content-type"));

        // Malformed JSON body.
        let mut malformed = json_request("PATCH", "/config/apps/http/servers/srv0/listen/0", "");
        malformed.body = Bytes::from_static(b"{not json");
        let response = admin.handle(malformed).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("decoding request body"));

        // `...` requires an array payload.
        let response = admin
            .handle(json_request(
                "POST",
                "/config/apps/http/servers/srv0/routes/...",
                json!("not-an-array"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("final element is not an array"));

        // Non-canonical and out-of-bounds array indexes are rejected.
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/00",
                json!(":8081"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("non-canonical array index"));

        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/9",
                json!(":8081"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("array index out of bounds"));
    }

    #[tokio::test]
    async fn post_config_root_replaces_and_delete_config_unloads() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        let response = admin
            .handle(json_request("POST", "/config/", json!({})))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        assert_eq!(get_config(&admin).await, json!({}));

        // PUT on /config/ conflicts with the existing wrapper key, matching Caddy.
        let response = admin
            .handle(json_request("PUT", "/config/", json!({})))
            .await;
        assert_eq!(response.status, StatusCode::CONFLICT);

        load(&admin, &valid_config()).await;
        assert!(is_running(admin.store()));

        // DELETE /config/ unloads the configuration (Caddy runs a nil config).
        let response = admin.handle(request("DELETE", "/config/", "")).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        assert!(admin.store().current().is_none());
        assert!(!is_running(admin.store()));
        assert_eq!(
            admin.handle(request("GET", "/config/", "")).await.body,
            Bytes::from_static(b"{}")
        );
    }

    #[tokio::test]
    async fn id_lookup_finds_routes_including_nested_subroutes() {
        let admin = admin();
        load(
            &admin,
            &config_with_routes(json!([
                {
                    "@id": "outer",
                    "handle": [{"handler": "subroute", "routes": [
                        {"@id": "inner", "handle": [{"handler": "static_response", "body": "in"}]}
                    ]}]
                },
                {"@id": "second", "handle": [{"handler": "static_response", "body": "2"}]}
            ])),
        )
        .await;

        let response = admin.handle(request("GET", "/id/inner", "")).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let route: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(route["@id"], "inner");
        assert_eq!(route["handle"][0]["body"], "in");

        // A sub-path below the addressed object works too.
        let response = admin
            .handle(request("GET", "/id/outer/handle/0/handler", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!("subroute")
        );

        let response = admin.handle(request("GET", "/id/second", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let route: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(route["handle"][0]["body"], "2");

        // Missing id: 404 with a clear message.
        let response = admin.handle(request("GET", "/id/unknown-id", "")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(error["error"], "unknown object ID 'unknown-id'");

        // Missing id segment: 400, matching Caddy.
        let response = admin.handle(request("GET", "/id/", "")).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn id_addressing_supports_partial_updates_and_duplicate_detection() {
        let admin = admin();
        load(
            &admin,
            &config_with_routes(json!([
                {"@id": "route1", "handle": [{"handler": "static_response", "body": "one"}]}
            ])),
        )
        .await;

        // PATCH addressed by id replaces the object.
        let response = admin
            .handle(json_request(
                "PATCH",
                "/id/route1",
                json!({"@id": "route1", "handle": [{"handler": "static_response", "body": "patched"}]}),
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        assert_eq!(
            config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
            "patched"
        );

        // PUT addressed by id expands to the route's index and inserts there.
        let response = admin
            .handle(json_request(
                "PUT",
                "/id/route1",
                json!({"@id": "route0", "handle": [{"handler": "static_response", "body": "zero"}]}),
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        let config = get_config(&admin).await;
        let ids: Vec<&str> = config["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| route["@id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["route0", "route1"]);

        // Appending a duplicate id is rejected with Caddy's indexing error.
        let response = admin
            .handle(json_request(
                "POST",
                "/id/route1",
                json!({"@id": "route1", "handle": [{"handler": "static_response"}]}),
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("duplicate ID 'route1'"));
        // The rejected duplicate did not create a generation: load, PATCH, PUT = 3.
        assert_eq!(admin.store().current().unwrap().id(), 3);
    }

    #[tokio::test]
    async fn load_rejects_duplicate_ids_on_non_route_objects() {
        let admin = admin();
        let response = load(
            &admin,
            &json!({
                "apps": {"http": {"servers": {
                    "srv0": {"@id": "dup", "listen": [":8080"], "routes": []},
                    "srv1": {"@id": "dup", "listen": [":8081"], "routes": []}
                }}}
            })
            .to_string(),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("duplicate ID 'dup'"));
        assert!(admin.store().current().is_none());
    }

    #[tokio::test]
    async fn origin_enforcement_allows_configured_origins_and_rejects_others() {
        let admin = admin();
        let config = json!({
            "admin": {
                "listen": "localhost:2019",
                "enforce_origin": true,
                "origins": ["https://allowed.example"]
            },
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin
            .handle(with_origin(
                request("GET", "/config/", ""),
                "https://allowed.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://allowed.example"
        );

        let response = admin
            .handle(with_origin(
                request("GET", "/config/", ""),
                "https://evil.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(error["error"]
            .as_str()
            .unwrap()
            .contains("client is not allowed to access from origin 'https://evil.example'"));
        assert!(is_running(admin.store()));

        // Missing Origin is rejected while enforcement is on.
        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn origin_header_is_checked_without_enforce_origin() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let response = admin
            .handle(with_origin(
                request("GET", "/healthz", ""),
                "https://evil.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        // No Origin header: allowed.
        assert_eq!(
            admin.handle(request("GET", "/healthz", "")).await.status,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn null_origin_is_a_bad_request() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let response = admin
            .handle(with_origin(request("GET", "/healthz", ""), "null"))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("null Origin"));
        assert!(is_running(admin.store()));
    }

    #[tokio::test]
    async fn default_loopback_origins_apply_without_explicit_origins() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        // valid_config's admin.listen is localhost:2019, so all loopback spellings are allowed.
        for origin in [
            "http://localhost:2019",
            "http://127.0.0.1:2019",
            "http://[::1]:2019",
        ] {
            let response = admin
                .handle(with_origin(request("GET", "/healthz", ""), origin))
                .await;
            assert_eq!(response.status, StatusCode::OK, "origin {origin}");
        }
        let response = admin
            .handle(with_origin(
                request("GET", "/healthz", ""),
                "http://localhost:2020",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn explicit_startup_policy_overrides_the_active_config() {
        let policy = OriginPolicy::from_admin(Some(&caddy_rs_core::AdminConfig {
            enforce_origin: true,
            origins: vec!["https://startup.example".to_string()],
            ..Default::default()
        }));
        let admin = AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
            .with_origin_policy(policy);
        let response = admin
            .handle(with_origin(
                request("GET", "/healthz", ""),
                "https://startup.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        let response = admin
            .handle(with_origin(
                request("GET", "/healthz", ""),
                "https://other.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_the_shared_registry() {
        let admin = admin();
        // The server runtime instruments this same registry; populate it the way it would.
        let metrics = HttpMetrics::new(admin.metrics());
        metrics
            .request_finished(&RequestObservation::new(
                "srv0",
                "route0",
                "GET",
                200,
                Duration::from_millis(5),
            ))
            .unwrap();
        let guard = metrics.request_started("srv0", "route0").unwrap();

        let response = admin.handle(request("GET", "/metrics", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(METRICS_CONTENT_TYPE)
        );
        let body = body_string(&response);
        assert!(
            body.contains("# TYPE caddy_http_requests_total counter"),
            "missing counter family: {body}"
        );
        assert!(
            body.contains("caddy_http_requests_total{handler=\"route0\",server=\"srv0\"} 1"),
            "missing counter series: {body}"
        );
        assert!(
            body.contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 1"),
            "missing in-flight gauge: {body}"
        );
        assert!(
            body.contains("# TYPE caddy_http_request_duration_seconds histogram"),
            "missing latency histogram: {body}"
        );

        // Deterministic: scraping twice yields byte-identical output.
        let second = body_string(&admin.handle(request("GET", "/metrics", "")).await);
        assert_eq!(body, second);

        drop(guard);
        let after = body_string(&admin.handle(request("GET", "/metrics", "")).await);
        assert!(
            after.contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 0")
        );
    }

    #[tokio::test]
    async fn metrics_registry_can_be_injected_before_population() {
        let registry = MetricsRegistry::new();
        let admin = admin().with_metrics(registry.clone());
        let metrics = HttpMetrics::new(admin.metrics());
        metrics
            .proxy_request_finished(&ProxyObservation {
                upstream: "10.0.0.5:8080",
                method: "GET",
                status: 200,
                duration: Duration::from_millis(20),
                success: true,
            })
            .unwrap();

        // Both handles share one registry: the admin serves what the runtime recorded.
        assert_eq!(admin.metrics().render(), registry.render());
        let body = body_string(&admin.handle(request("GET", "/metrics", "")).await);
        assert!(
            body.contains("caddy_rs_proxy_requests_total{code=\"200\",method=\"GET\",upstream=\"10.0.0.5:8080\"} 1"),
            "missing proxy series: {body}"
        );
    }
}
