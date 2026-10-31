//! Caddy-compatible admin API (logic layer).
//!
//! The admin API is an architectural feature, not a convenience: it is how a running process
//! takes a new configuration without restarting. This crate implements the request semantics
//! against [`caddy_rs_core::GenerationStore`] and is transport-agnostic so it can be unit-tested;
//! `caddy-rs-server` binds it to a hyper listener.
//!
//! Implemented endpoints (Caddy v2 admin API surface):
//!
//! | Endpoint | Behaviour |
//! |---|---|
//! | `GET /config/` | Current configuration as JSON (`{}` when no generation is active) |
//! | `GET /config/<path>` | JSON traversal by object key or array index |
//! | `POST /load` | Validate, provision, and atomically activate a configuration |
//! | `POST /stop` | Deactivate the running configuration |
//! | `GET /metrics` | 501 until the observability workstream lands |
//!
//! `GET /id/<id>`, `/adapt`, and partial `PATCH`/`PUT`/`DELETE` updates are tracked by the admin
//! workstream and documented in `docs/compatibility/CONFIGURATION.md`.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{drain, Config, GenerationStore, LifecycleState};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

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
}

/// Admin API logic bound to a generation store.
#[derive(Debug, Clone)]
pub struct AdminApi {
    store: Arc<GenerationStore>,
    drain_timeout: Duration,
    reload_notify: Option<Arc<tokio::sync::Notify>>,
}

impl AdminApi {
    /// Create an admin API for a store.
    pub fn new(store: Arc<GenerationStore>) -> Self {
        Self {
            store,
            drain_timeout: Duration::from_secs(30),
            reload_notify: None,
        }
    }

    /// Wake the runtime supervisor immediately after a successful load/stop instead of waiting
    /// for its poll interval.
    pub fn with_reload_notify(mut self, notify: Arc<tokio::sync::Notify>) -> Self {
        self.reload_notify = Some(notify);
        self
    }

    fn notify_reload(&self) {
        if let Some(notify) = &self.reload_notify {
            notify.notify_one();
        }
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

    /// Handle one request.
    pub async fn handle(&self, request: AdminRequest) -> AdminResponse {
        let (path, query) = match request.path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.path.as_str(), None),
        };
        let _ = query;
        let method = request.method.as_str();

        if path == "/config/" || path == "/config" {
            if method != "GET" {
                return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
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
                return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
            }
            let current = match self.store.current() {
                Some(generation) => generation.config().to_value().unwrap_or_else(|_| json!({})),
                None => json!({}),
            };
            return match navigate(&current, pointer) {
                Some(value) => AdminResponse::json(StatusCode::OK, &value),
                None => AdminResponse::text(
                    StatusCode::NOT_FOUND,
                    format!("config path `{pointer}` not found"),
                ),
            };
        }

        match path {
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
                match self.store.load(config) {
                    Ok(loaded) => {
                        let replaced = loaded.replaced;
                        if let Some(replaced) = replaced {
                            let timeout = self.drain_timeout;
                            tokio::spawn(async move {
                                let _ = drain(&replaced, timeout).await;
                            });
                        }
                        self.notify_reload();
                        AdminResponse::empty(StatusCode::OK)
                    }
                    Err(error) => AdminResponse::text(
                        StatusCode::BAD_REQUEST,
                        format!("configuration rejected: {error}"),
                    ),
                }
            }
            "/stop" => {
                if method != "POST" {
                    return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let stopped = self.store.stop();
                if let Some(generation) = stopped {
                    let timeout = self.drain_timeout;
                    tokio::spawn(async move {
                        let _ = drain(&generation, timeout).await;
                    });
                }
                self.notify_reload();
                AdminResponse::empty(StatusCode::OK)
            }
            "/metrics" => AdminResponse::text(
                StatusCode::NOT_IMPLEMENTED,
                "metrics are tracked by the observability workstream (ADMIN-METRICS)",
            ),
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
}

/// Navigate a JSON document by `/`-separated object keys or numeric array indexes.
fn navigate(root: &Value, pointer: &str) -> Option<Value> {
    let mut current = root.clone();
    for segment in pointer.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        current = match current {
            Value::Object(mut object) => object.remove(segment)?,
            Value::Array(array) => {
                let index: usize = segment.parse().ok()?;
                array.into_iter().nth(index)?
            }
            _ => return None,
        };
    }
    Some(current)
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

    #[tokio::test]
    async fn load_then_read_config_and_paths() {
        let admin = admin();
        let response = admin
            .handle(request("POST", "/load", &valid_config()))
            .await;
        assert_eq!(response.status, StatusCode::OK);

        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let config: Value = serde_json::from_slice(&response.body).unwrap();
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
        admin
            .handle(request("POST", "/load", &valid_config()))
            .await;
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
        assert!(String::from_utf8_lossy(&response.body).contains("nope"));
        assert!(is_running(admin.store()));
    }

    #[tokio::test]
    async fn stop_deactivates_the_generation() {
        let admin = admin();
        admin
            .handle(request("POST", "/load", &valid_config()))
            .await;
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
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn navigate_handles_arrays_and_objects() {
        let value = json!({"apps": {"http": {"servers": {"srv0": {"listen": [":443"]}}}}});
        assert_eq!(
            navigate(&value, "apps/http/servers/srv0/listen/0"),
            Some(json!(":443"))
        );
        assert_eq!(navigate(&value, "apps/http/nope"), None);
    }
}
