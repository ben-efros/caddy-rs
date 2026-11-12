//! Black-box HTTP tests for certificate issuance jobs (`/api/v1/certificates/issue`).
//!
//! Everything runs in-process: a fake caddy admin accepts the applied config and the fake
//! certificate inventory is mutated by that load, exactly like the data plane would after it
//! attempted automatic HTTPS. No ACME and no network.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum_test::TestServer;
use caddy_rs_pm_api::{
    create_router, ApiState, CertificateIntentSummary, CertificateInventorySource,
    CertificateRecord, InventoryError, IssuanceFailure, IssuanceJob, IssuanceJobStatus,
};
use caddy_rs_pm_runtime::{
    CaddyAdmin, ConfigApplyService, ConfigSettings, PmRuntime, RuntimeConfig,
};
use tempfile::TempDir;

const DOMAIN: &str = "jobs.example.test";

fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    i64::try_from(seconds).expect("timestamp fits i64")
}

// ---------------------------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct InventoryState {
    records: Vec<CertificateRecord>,
    failure: Option<IssuanceFailure>,
}

/// What the fake data plane observes after it accepts a config load.
#[derive(Clone, Copy)]
enum AdminMode {
    /// Automatic HTTPS succeeded: a covering certificate appears.
    Issued,
    /// Automatic HTTPS failed: the inventory reports an ACME challenge error.
    ChallengeFailed,
    /// Nothing is ever reported (exercises the timeout path).
    Silent,
}

#[derive(Clone)]
struct FakeInventory(Arc<Mutex<InventoryState>>);

impl FakeInventory {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(InventoryState::default())))
    }

    fn insert_covering(&self) {
        let mut state = self.0.lock().expect("lock inventory");
        state.failure = None;
        state.records.push(CertificateRecord {
            domains: vec![DOMAIN.to_string()],
            sans: Vec::new(),
            issuer: "local".to_string(),
            expires_at_unix: Some(now_unix() + 7 * 24 * 60 * 60),
            source: "managed".to_string(),
            renewal_error: None,
        });
    }

    fn insert_failure(&self) {
        let mut state = self.0.lock().expect("lock inventory");
        state.failure = Some(IssuanceFailure {
            domains: vec![DOMAIN.to_string()],
            failed_at_unix: now_unix(),
            error: format!("fake ACME challenge failure for {DOMAIN}"),
        });
    }
}

impl CertificateInventorySource for FakeInventory {
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, InventoryError> {
        Ok(self.0.lock().expect("lock inventory").records.clone())
    }

    fn last_issuance_failure(&self) -> Result<Option<IssuanceFailure>, InventoryError> {
        Ok(self.0.lock().expect("lock inventory").failure.clone())
    }
}

#[derive(Clone)]
struct FakeAdmin {
    current: Arc<Mutex<serde_json::Value>>,
    inventory: FakeInventory,
    mode: AdminMode,
}

#[async_trait::async_trait]
impl CaddyAdmin for FakeAdmin {
    type Error = caddy_rs_pm_runtime::AdminError;

    async fn load(
        &self,
        config: &serde_json::Value,
    ) -> Result<(), caddy_rs_pm_runtime::AdminError> {
        *self.current.lock().expect("lock admin config") = config.clone();
        match self.mode {
            AdminMode::Issued => self.inventory.insert_covering(),
            AdminMode::ChallengeFailed => self.inventory.insert_failure(),
            AdminMode::Silent => {}
        }
        Ok(())
    }

    async fn current(&self) -> Result<serde_json::Value, caddy_rs_pm_runtime::AdminError> {
        Ok(self.current.lock().expect("lock admin config").clone())
    }
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    _dir: TempDir,
    runtime: PmRuntime,
    server: TestServer,
}

fn harness_with(
    mode: AdminMode,
    timeout: Duration,
    with_applier: bool,
    with_inventory: bool,
) -> Harness {
    let temp_dir = TempDir::new().expect("create temp dir");
    let runtime =
        PmRuntime::open(RuntimeConfig::new(temp_dir.path().join("data"))).expect("open runtime");
    let inventory = FakeInventory::new();
    let admin = FakeAdmin {
        current: Arc::new(Mutex::new(serde_json::Value::Null)),
        inventory: inventory.clone(),
        mode,
    };

    let mut state = ApiState::new(runtime.clone()).with_issuance_timeout(timeout);
    if with_applier {
        let applier =
            ConfigApplyService::new(runtime.clone(), Arc::new(admin), ConfigSettings::default());
        state = state.with_applier(applier);
    }
    if with_inventory {
        state = state.with_inventory(Arc::new(inventory));
    }

    let app = create_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    Harness {
        _dir: temp_dir,
        runtime,
        server: TestServer::new(app),
    }
}

fn harness(mode: AdminMode) -> Harness {
    harness_with(mode, Duration::from_secs(5), true, true)
}

fn auto_host_body(policy_id: u64) -> serde_json::Value {
    serde_json::json!({
        "domains": [DOMAIN],
        "tls": { "mode": "auto", "autoPolicyId": policy_id },
        "spec": {
            "kind": "proxy",
            "spec": {
                "upstream": { "scheme": "http", "host": "127.0.0.1", "port": 65535 },
                "websocket": false,
                "preserveHost": true
            }
        }
    })
}

async fn create_intent(server: &TestServer) -> CertificateIntentSummary {
    let response = server
        .post("/api/v1/certificates/intent")
        .json(&serde_json::json!({
            "domains": [DOMAIN],
            "issuer": "letsencrypt",
            "challenge": "http01"
        }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "create intent: {}",
        response.text()
    );
    response.json()
}

async fn create_auto_host(server: &TestServer, policy_id: u64) -> u64 {
    let response = server
        .post("/api/v1/hosts")
        .json(&auto_host_body(policy_id))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "create auto host: {}",
        response.text()
    );
    let body: serde_json::Value = response.json();
    body["id"].as_u64().expect("host id")
}

/// Create the intent + auto-TLS host and submit an issuance job; returns the job location path.
async fn submit_job(harness: &Harness) -> (String, u64) {
    let intent = create_intent(&harness.server).await;
    let host_id = create_auto_host(&harness.server, intent.policy_id).await;
    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": host_id }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::ACCEPTED,
        "issue: {}",
        response.text()
    );
    let location = response
        .header("location")
        .to_str()
        .expect("ascii location")
        .to_owned();
    (location, host_id)
}

/// Poll the job until it leaves `pending`, panicking with the last body on exhaustion.
async fn wait_for_job(server: &TestServer, location: &str) -> IssuanceJob {
    let start = std::time::Instant::now();
    loop {
        let response = server.get(location).await;
        assert_eq!(
            response.status_code(),
            StatusCode::OK,
            "get job {location}: {}",
            response.text()
        );
        let job: IssuanceJob = response.json();
        if job.status != IssuanceJobStatus::Pending {
            return job;
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("job still pending after 5s: {job:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// 1. success
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_job_succeeds_and_records_the_certificate_and_revision() {
    let harness = harness(AdminMode::Issued);
    let (location, host_id) = submit_job(&harness).await;
    let job = wait_for_job(&harness.server, &location).await;

    assert_eq!(job.status, IssuanceJobStatus::Issued, "job: {job:?}");
    assert_eq!(job.host_id, host_id);
    assert_eq!(job.domains, vec![DOMAIN.to_string()]);
    assert_eq!(job.error, None);

    let certificate = job.certificate.as_ref().expect("certificate recorded");
    assert_eq!(certificate.issuer, "local");
    assert_eq!(certificate.source, "managed");
    assert_eq!(certificate.domains, vec![DOMAIN.to_string()]);

    assert_eq!(job.revision, Some(1), "applied revision recorded: {job:?}");
    let config_hash = job.config_hash.as_deref().expect("config hash recorded");
    assert!(!config_hash.is_empty(), "config hash is not empty");
}

// ---------------------------------------------------------------------------------------------
// 2. ACME challenge failure
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_job_reports_the_exact_acme_challenge_failure_text() {
    let harness = harness(AdminMode::ChallengeFailed);
    let (location, _host_id) = submit_job(&harness).await;
    let job = wait_for_job(&harness.server, &location).await;

    assert_eq!(job.status, IssuanceJobStatus::Failed, "job: {job:?}");
    assert_eq!(
        job.error.as_deref(),
        Some(
            format!("automatic HTTPS issuance failed: fake ACME challenge failure for {DOMAIN}")
                .as_str()
        ),
        "the data plane failure text must be forwarded verbatim"
    );
    assert!(job.certificate.is_none());
}

// ---------------------------------------------------------------------------------------------
// 3. timeout
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_job_times_out_when_the_inventory_never_reports() {
    let harness = harness_with(AdminMode::Silent, Duration::from_millis(300), true, true);
    let (location, _host_id) = submit_job(&harness).await;
    let job = wait_for_job(&harness.server, &location).await;

    assert_eq!(job.status, IssuanceJobStatus::Failed, "job: {job:?}");
    let error = job.error.as_deref().expect("timeout error recorded");
    assert!(
        error.contains("timed out after"),
        "unexpected timeout error: {error}"
    );
    assert!(job.certificate.is_none());
}

// ---------------------------------------------------------------------------------------------
// 4. validation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_rejects_invalid_requests() {
    // Non-auto-TLS host => 409.
    let harness = harness(AdminMode::Issued);
    let dead = harness
        .server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["plain.example.test"],
            "spec": { "kind": "dead" }
        }))
        .await;
    assert_eq!(dead.status_code(), StatusCode::CREATED, "{}", dead.text());
    let dead_host_id = dead.json::<serde_json::Value>()["id"]
        .as_u64()
        .expect("host id");
    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": dead_host_id }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CONFLICT,
        "non-auto host: {}",
        response.text()
    );

    // Unknown host => 404.
    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": 9999 }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::NOT_FOUND,
        "missing host: {}",
        response.text()
    );

    // Unknown field in the body => 400.
    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": 1, "surprise": true }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::BAD_REQUEST,
        "unknown body field: {}",
        response.text()
    );

    // Unknown job id => 404.
    let response = harness.server.get("/api/v1/certificates/jobs/9999").await;
    assert_eq!(
        response.status_code(),
        StatusCode::NOT_FOUND,
        "unknown job: {}",
        response.text()
    );

    // No applier => 503.
    let no_applier = harness_with(AdminMode::Silent, Duration::from_secs(5), false, true);
    let response = no_applier
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": 1 }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no applier: {}",
        response.text()
    );

    // No inventory => 503.
    let no_inventory = harness_with(AdminMode::Silent, Duration::from_secs(5), true, false);
    let response = no_inventory
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": 1 }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no inventory: {}",
        response.text()
    );
}

// ---------------------------------------------------------------------------------------------
// 5. protocol: 202 + Location + strong ETag, 304, 412
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_job_protocol_uses_location_strong_etag_and_preconditions() {
    let harness = harness(AdminMode::Issued);
    let intent = create_intent(&harness.server).await;
    let host_id = create_auto_host(&harness.server, intent.policy_id).await;

    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": host_id }))
        .await;
    assert_eq!(response.status_code(), StatusCode::ACCEPTED);
    let location = response
        .header("location")
        .to_str()
        .expect("ascii location")
        .to_owned();
    let created: IssuanceJob = response.json();
    assert_eq!(
        location,
        format!("/api/v1/certificates/jobs/{}", created.id),
        "Location points at the job"
    );
    let posted_etag = response
        .header("etag")
        .to_str()
        .expect("ascii etag")
        .to_owned();
    assert!(
        posted_etag.starts_with('"'),
        "strong ETag expected: {posted_etag}"
    );
    assert!(posted_etag.starts_with(&format!("\"j{}-", created.id)));

    // Wait for a terminal body so the validator is stable between requests.
    let job = wait_for_job(&harness.server, &location).await;
    assert_eq!(job.status, IssuanceJobStatus::Issued, "job: {job:?}");

    let current = harness.server.get(location.as_str()).await;
    assert_eq!(current.status_code(), StatusCode::OK);
    let etag = current
        .header("etag")
        .to_str()
        .expect("ascii etag")
        .to_owned();
    assert!(etag.starts_with(&format!("\"j{}-", job.id)), "etag: {etag}");

    let cached = harness
        .server
        .get(location.as_str())
        .add_header("if-none-match", etag.as_str())
        .await;
    assert_eq!(
        cached.status_code(),
        StatusCode::NOT_MODIFIED,
        "If-None-Match match: {}",
        cached.text()
    );

    let stale = harness
        .server
        .get(location.as_str())
        .add_header("if-match", "\"j0-stale\"")
        .await;
    assert_eq!(
        stale.status_code(),
        StatusCode::PRECONDITION_FAILED,
        "stale If-Match: {}",
        stale.text()
    );
}

// ---------------------------------------------------------------------------------------------
// 6. an existing auto policy is reused, not duplicated
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn issuance_reuses_the_existing_auto_policy() {
    let harness = harness(AdminMode::Issued);
    let intent = create_intent(&harness.server).await;
    assert_eq!(intent.policy_id, 1, "the intent created policy 1");
    let host_id = create_auto_host(&harness.server, intent.policy_id).await;

    let response = harness
        .server
        .post("/api/v1/certificates/issue")
        .json(&serde_json::json!({ "hostId": host_id }))
        .await;
    assert_eq!(response.status_code(), StatusCode::ACCEPTED);
    let location = response
        .header("location")
        .to_str()
        .expect("ascii location")
        .to_owned();
    let job = wait_for_job(&harness.server, &location).await;

    assert_eq!(job.status, IssuanceJobStatus::Issued, "job: {job:?}");
    assert_eq!(
        job.policy_id, intent.policy_id,
        "the job records the pre-existing policy id"
    );

    let policies = harness.runtime.policies().list().expect("list policies");
    assert_eq!(
        policies.len(),
        1,
        "no duplicate auto policy was created: {policies:?}"
    );
}
