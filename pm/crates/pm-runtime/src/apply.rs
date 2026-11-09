//! Transactional config apply pipeline.
//!
//! The PM assembles a deterministic config and hands it to the reusable pipeline in
//! `caddy-rs-config-tx`, which stages, diffs, loads, verifies and restores. This module owns the
//! PM-specific pieces: the loopback admin client and the durable `config_revisions` record. No
//! admin response body, certificate PEM, or private key is ever stored or echoed.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use caddy_rs_config_tx::{
    ApplyFailure, ConfigApplyPipeline, ConfigTarget, InMemoryRevisionStore, StagedConfig,
};
use caddy_rs_pm_config::ConfigSettings;
use caddy_rs_pm_state::{StateError, StateStore, Transaction};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{PmRuntime, RuntimeError};

/// State collection holding durable config apply revisions.
pub const CONFIG_REVISIONS: &str = "config_revisions";

/// Maximum accepted admin `/config/` response size.
const MAX_ADMIN_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// One durable apply attempt. Failed attempts are kept as audit evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRevision {
    pub revision: u64,
    pub hash: String,
    pub status: ConfigApplyStatus,
    pub changed: bool,
    pub recorded_at_unix: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Outcome of an apply attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigApplyStatus {
    Applied,
    Failed,
}

/// Result of a successful apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyOutcome {
    pub revision: u64,
    pub hash: String,
    pub changed: bool,
}

/// Errors from the apply pipeline. Messages never include the config or admin response body.
#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("config assembly failed: {0}")]
    Assemble(#[from] RuntimeError),
    #[error("config pipeline failed: {0}")]
    Pipeline(#[from] ApplyFailure<AdminError>),
    #[error("config state failed: {0}")]
    State(#[from] StateError),
    #[error("config revision serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Errors from the caddy-rs admin client.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("invalid caddy admin URL: {0}")]
    InvalidUrl(String),
    #[error("caddy admin URL host `{0}` is not loopback; set an explicit non-loopback override")]
    NonLoopback(String),
    #[error("caddy admin transport failed")]
    Transport(#[from] reqwest::Error),
    #[error("caddy admin returned HTTP {0}")]
    Http(u16),
    #[error("caddy admin response exceeded the size limit")]
    ResponseTooLarge,
    #[error("caddy admin returned an invalid JSON object")]
    InvalidResponse,
}

/// The narrow admin surface used by the apply service; the reusable trait lives in `config-tx`.
pub use caddy_rs_config_tx::ConfigTarget as CaddyAdmin;

/// Loopback-only HTTP client for the caddy-rs admin API.
///
/// The default is HTTP on a loopback address. Plain HTTP is intentional: the admin listener is
/// local, and Caddy's admin endpoint is not meant to be exposed. TLS is not configured here
/// because the PM does not own the admin certificate.
pub struct HttpCaddyAdmin {
    client: Client,
    base: Url,
}

impl HttpCaddyAdmin {
    /// Build a client for `url`; non-loopback hosts require `allow_non_loopback`.
    pub fn new(url: &str, allow_non_loopback: bool) -> Result<Self, AdminError> {
        let base = Url::parse(url).map_err(|_| AdminError::InvalidUrl("not a URL".to_string()))?;
        if base.scheme() != "http" {
            return Err(AdminError::InvalidUrl(
                "admin URL must use http on the loopback listener".to_string(),
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(AdminError::InvalidUrl(
                "admin URL must not contain userinfo".to_string(),
            ));
        }
        if base.query().is_some() || base.fragment().is_some() || base.path() != "/" {
            return Err(AdminError::InvalidUrl(
                "admin URL must be an origin without path, query or fragment".to_string(),
            ));
        }
        let host = base
            .host_str()
            .ok_or_else(|| AdminError::InvalidUrl("admin URL has no host".to_string()))?;
        if !allow_non_loopback && !is_loopback_host(host) {
            return Err(AdminError::NonLoopback(host.to_string()));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { client, base })
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(path);
        url
    }
}

fn is_loopback_host(host: &str) -> bool {
    // Only a literal loopback IP is accepted. A hostname such as `localhost` is resolved by the
    // HTTP client and can be redirected by DNS; pinning it here would be a false guarantee.
    let bare = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[async_trait]
impl ConfigTarget for HttpCaddyAdmin {
    type Error = AdminError;

    async fn load(&self, config: &Value) -> Result<(), AdminError> {
        let response = self
            .client
            .post(self.endpoint("/load"))
            .json(config)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(AdminError::Http(response.status().as_u16()));
        }
        Ok(())
    }

    async fn current(&self) -> Result<Value, AdminError> {
        let mut response = self.client.get(self.endpoint("/config/")).send().await?;
        if !response.status().is_success() {
            return Err(AdminError::Http(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_ADMIN_RESPONSE_BYTES as u64)
        {
            return Err(AdminError::ResponseTooLarge);
        }
        // Stream rather than `bytes()`: a missing or lying Content-Length must not let the admin
        // endpoint make the PM allocate an unbounded response.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > MAX_ADMIN_RESPONSE_BYTES {
                return Err(AdminError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&body).map_err(|_| AdminError::InvalidResponse)?;
        if !value.is_object() {
            return Err(AdminError::InvalidResponse);
        }
        Ok(value)
    }
}

/// Config apply pipeline over one PM runtime.
pub struct ConfigApplyService {
    runtime: PmRuntime,
    admin: Arc<dyn CaddyAdmin<Error = AdminError>>,
    settings: ConfigSettings,
    pipeline: ConfigApplyPipeline<InMemoryRevisionStore>,
}

impl ConfigApplyService {
    /// Build a pipeline with the given admin implementation.
    pub fn new(
        runtime: PmRuntime,
        admin: Arc<dyn CaddyAdmin<Error = AdminError>>,
        settings: ConfigSettings,
    ) -> Self {
        Self {
            runtime,
            admin,
            settings,
            pipeline: ConfigApplyPipeline::new(InMemoryRevisionStore::new()),
        }
    }

    /// Build a pipeline backed by the loopback HTTP admin client.
    pub fn with_http(
        runtime: PmRuntime,
        url: &str,
        allow_non_loopback: bool,
        settings: ConfigSettings,
    ) -> Result<Self, AdminError> {
        let admin = Arc::new(HttpCaddyAdmin::new(url, allow_non_loopback)?);
        Ok(Self::new(runtime, admin, settings))
    }

    /// Assemble, load, verify and record one config generation.
    ///
    /// The ordering rules (baseline capture, load, verification, restore, transaction apply) live
    /// in `caddy-rs-config-tx`; this method owns only the PM-specific assembly and durable revision
    /// record. If the durable record fails after the core pipeline activated a generation, the
    /// previous generation is restored before returning the error.
    pub async fn apply(&self) -> Result<ApplyOutcome, ApplyError> {
        let config = self.runtime.assemble(self.settings)?;
        let previous = self.pipeline.tx().active_generation();
        match self
            .pipeline
            .apply(config.clone(), self.admin.as_ref())
            .await
        {
            Ok(outcome) => {
                let changed = outcome.changed;
                let hash = outcome.generation.hash;
                let baseline = outcome.baseline;
                match self
                    .record(ConfigApplyStatus::Applied, &hash, changed, None)
                    .await
                {
                    Ok(revision) => {
                        // A loaded certificate is serving; update local status only after the
                        // pipeline verified the config. A failed status write leaves it pending
                        // for a later retry and does not undo a verified apply.
                        let _ = self.runtime.certificates().mark_applied(unix_now());
                        Ok(ApplyOutcome {
                            revision,
                            hash,
                            changed,
                        })
                    }
                    Err(error) => {
                        // The pipeline verified the live config but the durable PM record failed.
                        // Restore exactly what the target served before this attempt; on a first
                        // apply that is the captured baseline, not `previous`.
                        let _ = self.admin.load(&baseline).await;
                        if let Some(previous) = previous.as_ref() {
                            let _ = self.pipeline.tx().rollback(previous.revision);
                        }
                        let _ = self.record_failure(&config, changed, &error).await;
                        Err(error)
                    }
                }
            }
            Err(failure) => {
                self.record_failure(&config, failure.changed, &failure)
                    .await?;
                Err(failure.into())
            }
        }
    }

    /// Durable apply history, newest last.
    pub fn revisions(&self) -> Result<Vec<ConfigRevision>, ApplyError> {
        let mut revisions = self
            .runtime
            .state_store()
            .scan(CONFIG_REVISIONS, "")?
            .into_iter()
            .filter_map(|document| serde_json::from_value::<ConfigRevision>(document.value).ok())
            .collect::<Vec<_>>();
        revisions.sort_by_key(|revision| revision.revision);
        Ok(revisions)
    }

    async fn record_failure(
        &self,
        config: &Value,
        changed: bool,
        error: &(impl std::fmt::Display + ?Sized),
    ) -> Result<(), ApplyError> {
        let hash = StagedConfig::new(config.clone()).hash;
        let message = bounded_error(&error.to_string());
        self.record(ConfigApplyStatus::Failed, &hash, changed, Some(message))
            .await?;
        Ok(())
    }

    async fn record(
        &self,
        status: ConfigApplyStatus,
        hash: &str,
        changed: bool,
        error: Option<String>,
    ) -> Result<u64, ApplyError> {
        let store = self.runtime.state_store();
        for _ in 0..8 {
            let revision = next_revision(&store)?;
            let record = ConfigRevision {
                revision,
                hash: hash.to_string(),
                status,
                changed,
                recorded_at_unix: unix_now(),
                error: error.clone(),
            };
            let key = revision.to_string();
            let transaction = Transaction::new()
                .check_missing(CONFIG_REVISIONS, key.clone())
                .put(
                    CONFIG_REVISIONS,
                    key.clone(),
                    serde_json::to_value(&record)?,
                );
            match store.transact(transaction) {
                Ok(_) => return Ok(revision),
                Err(StateError::Conflict { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StateError::Unavailable("config revision allocation is contended".to_string()).into())
    }
}

fn next_revision(store: &Arc<dyn StateStore>) -> Result<u64, StateError> {
    let max = store
        .scan(CONFIG_REVISIONS, "")?
        .into_iter()
        .filter_map(|document| document.key.parse::<u64>().ok())
        .max()
        .unwrap_or(0);
    max.checked_add(1)
        .ok_or_else(|| StateError::Unavailable("config revision space exhausted".to_string()))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn bounded_error(message: &str) -> String {
    const MAX: usize = 512;
    if message.len() <= MAX {
        return message.to_string();
    }
    let mut end = MAX;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_config_tx::ApplyFailureKind;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    #[derive(Default)]
    struct FakeState {
        current: Value,
        loads: usize,
        fail_load: bool,
    }

    #[derive(Clone, Default)]
    struct FakeAdmin {
        state: Arc<StdMutex<FakeState>>,
    }

    impl FakeAdmin {
        fn set_fail(&self, fail: bool) {
            self.state.lock().unwrap().fail_load = fail;
        }
        fn loads(&self) -> usize {
            self.state.lock().unwrap().loads
        }
    }

    #[async_trait]
    impl ConfigTarget for FakeAdmin {
        type Error = AdminError;

        async fn load(&self, config: &Value) -> Result<(), AdminError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_load {
                // Fail one request, then allow the pipeline's restore load to succeed.
                state.fail_load = false;
                return Err(AdminError::Http(500));
            }
            state.current = config.clone();
            state.loads += 1;
            Ok(())
        }

        async fn current(&self) -> Result<Value, AdminError> {
            Ok(self.state.lock().unwrap().current.clone())
        }
    }

    fn service() -> (TempDir, ConfigApplyService, FakeAdmin) {
        let dir = TempDir::new().expect("temp dir");
        let runtime =
            PmRuntime::open(crate::RuntimeConfig::new(dir.path().join("data"))).expect("runtime");
        let admin = FakeAdmin::default();
        let service =
            ConfigApplyService::new(runtime, Arc::new(admin.clone()), ConfigSettings::default());
        (dir, service, admin)
    }

    #[tokio::test]
    async fn apply_loads_verifies_and_records_durable_revisions() {
        let (_dir, service, admin) = service();
        let first = service.apply().await.expect("first apply");
        assert_eq!(first.revision, 1);
        assert!(first.changed);
        assert_eq!(admin.loads(), 1);
        let revisions = service.revisions().expect("revisions");
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].status, ConfigApplyStatus::Applied);
        assert_eq!(revisions[0].hash, first.hash);

        let second = service.apply().await.expect("second apply");
        assert_eq!(second.revision, 2);
        assert!(
            !second.changed,
            "same assembled config has an empty route diff"
        );
        assert_eq!(admin.loads(), 2);
        assert_eq!(service.revisions().expect("revisions").len(), 2);
    }

    #[tokio::test]
    async fn durable_revisions_survive_a_runtime_reopen() {
        let (dir, service, admin) = service();
        service.apply().await.expect("apply");
        drop(service);

        let runtime =
            PmRuntime::open(crate::RuntimeConfig::new(dir.path().join("data"))).expect("reopen");
        let reopened = ConfigApplyService::new(runtime, Arc::new(admin), ConfigSettings::default());
        let revisions = reopened.revisions().expect("revisions");
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].status, ConfigApplyStatus::Applied);
    }

    #[tokio::test]
    async fn failed_load_keeps_the_previous_generation_and_records_failure() {
        let (_dir, service, admin) = service();
        service.apply().await.expect("initial apply");
        let before = admin.state.lock().unwrap().current.clone();
        admin.set_fail(true);
        let error = service.apply().await.expect_err("load fails");
        assert!(matches!(
            error,
            ApplyError::Pipeline(ApplyFailure {
                kind: ApplyFailureKind::Target(AdminError::Http(500)),
                ..
            })
        ));
        assert_eq!(admin.state.lock().unwrap().current, before);
        let revisions = service.revisions().expect("revisions");
        assert_eq!(
            revisions.last().expect("last").status,
            ConfigApplyStatus::Failed
        );
        assert_eq!(revisions.last().expect("last").revision, 2);
    }

    #[test]
    fn admin_urls_are_loopback_only_unless_explicitly_overridden() {
        assert!(HttpCaddyAdmin::new("http://127.0.0.1:2019", false).is_ok());
        assert!(HttpCaddyAdmin::new("http://localhost:2019", false).is_err());
        assert!(
            HttpCaddyAdmin::new("http://[::1]:2019", false).is_ok(),
            "ipv6: {:?}",
            HttpCaddyAdmin::new("http://[::1]:2019", false).err()
        );
        assert!(HttpCaddyAdmin::new("http://10.0.0.5:2019", false).is_err());
        assert!(HttpCaddyAdmin::new("http://0.0.0.0:2019", false).is_err());
        assert!(HttpCaddyAdmin::new("http://127.0.0.1.evil:2019", false).is_err());
        assert!(HttpCaddyAdmin::new("http://user:pass@127.0.0.1:2019", false).is_err());
        assert!(HttpCaddyAdmin::new("https://127.0.0.1:2019", false).is_err());
        assert!(HttpCaddyAdmin::new("http://127.0.0.1:2019/admin", false).is_err());
        assert!(
            HttpCaddyAdmin::new("http://127.0.0.1:2019?x=y", false).is_err(),
            "query strings must not be accepted"
        );
        assert!(HttpCaddyAdmin::new("http://10.0.0.5:2019", true).is_ok());
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::{
        extract::State as AxumState,
        http::StatusCode,
        routing::{get as axum_get, post as axum_post},
        Json as AxumJson, Router,
    };
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    type Sink = Arc<StdMutex<Value>>;

    async fn fake_load(
        AxumState(sink): AxumState<Sink>,
        AxumJson(body): AxumJson<Value>,
    ) -> StatusCode {
        *sink.lock().unwrap() = body;
        StatusCode::OK
    }

    async fn fake_current(AxumState(sink): AxumState<Sink>) -> AxumJson<Value> {
        AxumJson(sink.lock().unwrap().clone())
    }

    async fn huge_current() -> String {
        "x".repeat(MAX_ADMIN_RESPONSE_BYTES + 1)
    }

    #[tokio::test]
    async fn http_admin_posts_load_and_verifies_the_reported_config() {
        let sink: Sink = Arc::new(StdMutex::new(json!({})));
        let app = Router::new()
            .route("/load", axum_post(fake_load))
            .route("/config/", axum_get(fake_current))
            .with_state(Arc::clone(&sink));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let admin = HttpCaddyAdmin::new(&format!("http://{address}"), false).expect("client");
        let expected = json!({"apps": {"http": {"servers": {}}}});
        admin.load(&expected).await.expect("load");
        assert_eq!(*sink.lock().unwrap(), expected);
        assert_eq!(admin.current().await.expect("current"), expected);
        server.abort();
    }

    #[tokio::test]
    async fn http_admin_does_not_follow_admin_redirects() {
        async fn redirect_current() -> axum::response::Redirect {
            axum::response::Redirect::temporary("/followed")
        }
        async fn followed(AxumState(sink): AxumState<Sink>) -> AxumJson<Value> {
            *sink.lock().unwrap() = json!({"followed": true});
            AxumJson(json!({}))
        }

        let sink: Sink = Arc::new(StdMutex::new(json!({})));
        let app = Router::new()
            .route("/config/", axum_get(redirect_current))
            .route("/followed", axum_get(followed))
            .with_state(Arc::clone(&sink));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let admin = HttpCaddyAdmin::new(&format!("http://{address}"), false).expect("client");
        assert!(matches!(admin.current().await, Err(AdminError::Http(307))));
        assert_eq!(
            *sink.lock().unwrap(),
            json!({}),
            "redirect was not followed"
        );
        server.abort();
    }

    #[tokio::test]
    async fn http_admin_rejects_an_oversized_chunked_config_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .expect("headers");
            let chunk = vec![b'x'; 8192];
            let prefix = format!("{:x}\r\n", chunk.len());
            let mut sent = 0;
            while sent <= MAX_ADMIN_RESPONSE_BYTES {
                if socket.write_all(prefix.as_bytes()).await.is_err()
                    || socket.write_all(&chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
                sent += chunk.len();
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });

        let admin = HttpCaddyAdmin::new(&format!("http://{address}"), false).expect("client");
        assert!(matches!(
            admin.current().await,
            Err(AdminError::ResponseTooLarge)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn http_admin_rejects_an_oversized_config_response() {
        let app = Router::new().route("/config/", axum_get(huge_current));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let admin = HttpCaddyAdmin::new(&format!("http://{address}"), false).expect("client");
        assert!(matches!(
            admin.current().await,
            Err(AdminError::ResponseTooLarge)
        ));
        server.abort();
    }
}
