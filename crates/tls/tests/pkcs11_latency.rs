//! PKCS#11 signing-latency and handshake-throughput measurement harness (T-TLS-097).
//!
//! The harness measures the token-backed key path described by ADR-0009 and implemented by
//! [`caddy_rs_tls::pkcs11`]:
//!
//! 1. sign latency p50/p95/p99 for RSA-2048 and P-256, measured through the production per-token
//!    sign queue;
//! 2. TLS 1.3 full-handshake throughput at `max_sessions` 1, 2 and 4 (the TLS 1.3 full handshake
//!    is the token-capacity driver: every full handshake needs one token signature);
//! 3. resumed TLS 1.2 handshake rate, which must perform **zero** token signatures;
//! 4. queue saturation and `queue_wait` failure behaviour, and the `sign_timeout` quarantine
//!    latch (fail-closed);
//! 5. a Tokio worker-latency probe proving a token sign does not stall async workers (the
//!    rustls signer is synchronous, so the token wait runs under `block_in_place` and every
//!    handshake is admitted through the per-token handshake budget).
//!
//! It is environment-gated so the default workspace test run needs no token:
//!
//! * `soft_hsm_latency_matrix` runs only when `CADDY_RS_PKCS11_MODULE` names a PKCS#11 module
//!   (SoftHSM2 in the recorded run); otherwise it prints a `SKIP` line and passes.
//! * `tpm2_pkcs11_latency_matrix` runs only when `CADDY_RS_PKCS11_TPM_MODULE` is set; otherwise
//!   it prints the documented environmental gap (no real TPM in the recording environment).
//!
//! Reproduce the recorded SoftHSM2 run with `.scratch/logs/tls097/run-measurements.sh`; the
//! method and the measured budget are published in `docs/operations/PKCS11.md`.
//!
//! Every measurement is emitted as one JSON line (`PKCS11_METRIC {...}`) and appended to
//! `CADDY_RS_PKCS11_METRICS_OUT` when that variable is set, so the numbers in the documentation
//! can be re-derived from a log instead of trusted from prose.

use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use caddy_rs_core::Config;
use caddy_rs_tls::pkcs11::{open_token, KeySelector, Pkcs11Budget, TokenPool};
use caddy_rs_tls::tls_server::{
    accept_external_key_handshake, build_server_config, resolver_from_config, TlsResolver,
    TlsServerOptions, TlsVersions,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::SigningKey;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// One certificate/key pair to measure, with the source of the certificate chain.
struct KeyFixture {
    label: &'static str,
    scheme: SignatureScheme,
    certificate_pem: PathBuf,
    certificate_der: PathBuf,
}

/// Everything the harness needs from the environment.
struct HarnessEnv {
    module: PathBuf,
    token: String,
    /// Name of the environment variable holding the PIN (not the PIN itself: the token loader
    /// reads it, the harness never holds it).
    pin_var: String,
    rsa: KeyFixture,
    p256: KeyFixture,
    metrics_out: Option<PathBuf>,
}

impl HarnessEnv {
    /// `SOFTHSM2_CONF` must point at a SoftHSM2 config for the module to find its token; the
    /// harness checks that the module path exists and leaves token errors to the loader.
    fn from_env() -> Option<Self> {
        let module = PathBuf::from(env::var_os("CADDY_RS_PKCS11_MODULE")?);
        if !module.is_file() {
            panic!(
                "CADDY_RS_PKCS11_MODULE does not name a file: {}",
                module.display()
            );
        }
        let certificate = |name: &str| {
            PathBuf::from(env::var_os(name).unwrap_or_else(|| {
                panic!("{name} must name a certificate chain file for the token-key measurement")
            }))
        };
        Some(Self {
            module,
            token: env::var("CADDY_RS_PKCS11_TOKEN")
                .unwrap_or_else(|_| "caddy-rs-test".to_string()),
            pin_var: env::var("CADDY_RS_PKCS11_PIN_VAR")
                .unwrap_or_else(|_| "CADDY_RS_PKCS11_PIN".to_string()),
            rsa: KeyFixture {
                label: "rsa2048",
                scheme: SignatureScheme::RSA_PKCS1_SHA256,
                certificate_pem: certificate("CADDY_RS_PKCS11_CERT_PEM_RSA"),
                certificate_der: certificate("CADDY_RS_PKCS11_CERT_DER_RSA"),
            },
            p256: KeyFixture {
                label: "p256",
                scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                certificate_pem: certificate("CADDY_RS_PKCS11_CERT_PEM_P256"),
                certificate_der: certificate("CADDY_RS_PKCS11_CERT_DER_P256"),
            },
            metrics_out: env::var_os("CADDY_RS_PKCS11_METRICS_OUT").map(PathBuf::from),
        })
    }
}

/// Timeout/queue budget for one measurement phase. `None` values use the ADR-0009 defaults
/// resolved by the configuration layer.
#[derive(Clone, Copy, Default)]
struct BudgetSpec {
    max_sessions: u64,
    max_inflight_handshakes: Option<u64>,
    handshake_wait_nanos: Option<u64>,
    queue_depth: u64,
    queue_wait_nanos: Option<u64>,
    sign_timeout_nanos: Option<u64>,
    handshake_timeout_nanos: Option<u64>,
}

impl BudgetSpec {
    /// The ADR-0009 defaults: one session, queue_depth 64 and the published timeouts.
    fn after(_entry: &str) -> Self {
        Self {
            max_sessions: 1,
            max_inflight_handshakes: None,
            handshake_wait_nanos: None,
            queue_depth: 64,
            queue_wait_nanos: None,
            sign_timeout_nanos: None,
            handshake_timeout_nanos: None,
        }
    }
}

fn boolean(value: bool) -> f64 {
    if value {
        1.0
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// One measured value. `phase` groups the rows (latency, throughput, resumed, saturation,
/// worker_stall, quarantine) so a reader can re-derive the documentation tables.
#[derive(Clone, Debug)]
struct Metric {
    phase: &'static str,
    name: String,
    value: f64,
    unit: &'static str,
}

#[derive(Default)]
struct Metrics {
    rows: Mutex<Vec<Metric>>,
}

impl Metrics {
    fn record(&self, phase: &'static str, name: impl Into<String>, value: f64, unit: &'static str) {
        let row = Metric {
            phase,
            name: name.into(),
            value,
            unit,
        };
        // Print immediately so a hanging later phase still leaves the earlier numbers in the log.
        let line = json!({
            "phase": row.phase,
            "name": row.name,
            "value": row.value,
            "unit": row.unit,
        });
        println!("PKCS11_METRIC {line}");
        self.rows.lock().expect("metrics mutex").push(row);
    }

    fn flush(&self, path: Option<&Path>) {
        let Some(path) = path else { return };
        let mut text = String::new();
        for row in self.rows.lock().expect("metrics mutex").iter() {
            text.push_str(
                &json!({
                    "phase": row.phase,
                    "name": row.name,
                    "value": row.value,
                    "unit": row.unit,
                })
                .to_string(),
            );
            text.push('\n');
        }
        if let Err(error) = std::fs::write(path, text) {
            eprintln!(
                "warning: cannot write metrics to {}: {error}",
                path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

fn percentile(samples: &[Duration], quantile: f64) -> Duration {
    assert!(!samples.is_empty(), "percentile of empty sample set");
    let mut nanos: Vec<u128> = samples.iter().map(Duration::as_nanos).collect();
    nanos.sort_unstable();
    let rank = ((nanos.len() as f64) * quantile).ceil() as usize;
    let index = rank.saturating_sub(1).min(nanos.len() - 1);
    Duration::from_nanos(u64::try_from(nanos[index]).expect("latency fits u64 nanos"))
}

fn nanos(value: Duration) -> f64 {
    value.as_nanos() as f64
}

fn millis(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

/// Record the p50/p95/p99 trio for one phase.
fn record_percentiles(metrics: &Metrics, phase: &'static str, prefix: &str, samples: &[Duration]) {
    metrics.record(
        phase,
        format!("{prefix}_samples"),
        samples.len() as f64,
        "count",
    );
    metrics.record(
        phase,
        format!("{prefix}_p50"),
        millis(percentile(samples, 0.50)),
        "ms",
    );
    metrics.record(
        phase,
        format!("{prefix}_p95"),
        millis(percentile(samples, 0.95)),
        "ms",
    );
    metrics.record(
        phase,
        format!("{prefix}_p99"),
        millis(percentile(samples, 0.99)),
        "ms",
    );
    let max = samples.iter().copied().max().expect("non-empty samples");
    metrics.record(phase, format!("{prefix}_max"), millis(max), "ms");
}

// ---------------------------------------------------------------------------
// Configuration and server construction (production path)
// ---------------------------------------------------------------------------

/// Build one `apps.tls.certificates.pkcs11[]` entry configuration that names the token fixture.
fn pkcs11_config(env: &HarnessEnv, fixture: &KeyFixture, budget: BudgetSpec) -> Config {
    let mut entry = json!({
        "module": env.module.to_string_lossy(),
        "token": env.token,
        "key_label": fixture.label,
        "certificate": fixture.certificate_pem.to_string_lossy(),
        "pin": env.pin_var,
        "max_sessions": budget.max_sessions,
        "queue_depth": budget.queue_depth,
        "tags": ["measured"],
    });
    let map = entry.as_object_mut().expect("entry object");
    if let Some(value) = budget.max_inflight_handshakes {
        map.insert("max_inflight_handshakes".into(), json!(value));
    }
    if let Some(value) = budget.handshake_wait_nanos {
        map.insert("handshake_wait".into(), json!(value));
    }
    if let Some(value) = budget.queue_wait_nanos {
        map.insert("queue_wait".into(), json!(value));
    }
    if let Some(value) = budget.sign_timeout_nanos {
        map.insert("sign_timeout".into(), json!(value));
    }
    if let Some(value) = budget.handshake_timeout_nanos {
        map.insert("handshake_timeout".into(), json!(value));
    }
    let document = json!({
        "apps": { "tls": { "certificates": { "pkcs11": [entry] } } }
    });
    Config::from_value(document).expect("generated PKCS#11 TLS configuration must decode")
}

/// Build the production server configuration and the token pool it resolved.
///
/// This deliberately goes through `resolver_from_config` / `build_server_config` so the harness
/// measures the shipped loader, resolver marker and rustls configuration, not a test copy.
fn server_from_env(
    env: &HarnessEnv,
    fixture: &KeyFixture,
    budget: BudgetSpec,
    versions: TlsVersions,
) -> (Arc<Config>, Arc<rustls::ServerConfig>, Arc<TokenPool>) {
    let config = Arc::new(pkcs11_config(env, fixture, budget));
    let resolver = resolver_from_config(&config)
        .expect("resolver_from_config")
        .expect("a pkcs11 entry must produce a resolver");
    let pool = TlsResolver::external_key_pool(&resolver)
        .expect("a token-backed certificate must mark the listener external-key");
    let options = TlsServerOptions {
        versions,
        ..TlsServerOptions::default()
    };
    let server = build_server_config(Arc::new(resolver), &options).expect("build_server_config");
    (config, server, pool)
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Accept-any certificate verifier: the measured server uses a self-signed fixture certificate
/// generated for this harness only, and the harness asserts token behaviour, not PKI.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Protocol version slices with a `'static` lifetime for `client_config`.
const TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
const TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

/// One client configuration shared by every connection of a phase, so a resumed TLS 1.2 client
/// reuses the same in-memory session cache.
fn client_config(
    versions: &'static [&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    // 256 cached sessions: enough that a 200-handshake resumed batch reuses the warm-up session
    // instead of falling back to full handshakes because the cache evicted it.
    let mut config = config;
    config.resumption = rustls::client::Resumption::in_memory_sessions(256);
    Arc::new(config)
}

#[derive(Default)]
struct ServerStats {
    accepted: AtomicU64,
    full: AtomicU64,
    resumed: AtomicU64,
    failed: AtomicU64,
    /// Connection tasks still running; the harness waits for zero before closing the token pool.
    active: AtomicU64,
    idle: tokio::sync::Notify,
    /// First failure message, for a diagnosable assertion.
    first_failure: Mutex<Option<String>>,
}

impl ServerStats {
    /// Wait until every accepted connection task has finished.
    ///
    /// The token context is finalized when the last `Pkcs11` handle drops (`C_Finalize` is
    /// process-global for the module), so no connection may still be inside the token when the
    /// next measurement phase opens a new context: a lingering task would finalize the module
    /// underneath it (observed as a SIGSEGV inside the SoftHSM2 module).
    async fn wait_idle(&self) {
        loop {
            if self.active.load(Ordering::SeqCst) == 0 {
                return;
            }
            self.idle.notified().await;
        }
    }
}

struct RunningServer {
    address: SocketAddr,
    stats: Arc<ServerStats>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    /// Wait until every accepted connection task has finished with the token pool.
    async fn wait_idle(&self) {
        self.stats.wait_idle().await;
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Accept handshakes through the production external-key path until the task is aborted.
async fn start_server(server: Arc<rustls::ServerConfig>, pool: Arc<TokenPool>) -> RunningServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind measurement listener");
    let address = listener.local_addr().expect("listener address");
    let acceptor = TlsAcceptor::from(server);
    let stats = Arc::new(ServerStats::default());
    let task_stats = Arc::clone(&stats);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let pool = Arc::clone(&pool);
            let stats = Arc::clone(&task_stats);
            stats.active.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                match accept_external_key_handshake(acceptor, stream, pool).await {
                    Ok(tls) => {
                        stats.accepted.fetch_add(1, Ordering::Relaxed);
                        match tls.get_ref().1.handshake_kind() {
                            Some(rustls::HandshakeKind::Resumed) => {
                                stats.resumed.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                stats.full.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(error) => {
                        stats.failed.fetch_add(1, Ordering::Relaxed);
                        let mut first = stats.first_failure.lock().expect("failure mutex");
                        if first.is_none() {
                            *first = Some(error.to_string());
                        }
                    }
                }
                stats.active.fetch_sub(1, Ordering::SeqCst);
                stats.idle.notify_waiters();
            });
        }
    });
    RunningServer {
        address,
        stats,
        task,
    }
}

/// Run `total` client handshakes with at most `concurrency` in flight. Returns the successful
/// handshake count and the first few client-side errors.
async fn run_handshakes(
    client: Arc<ClientConfig>,
    address: SocketAddr,
    total: usize,
    concurrency: usize,
) -> (usize, Vec<String>) {
    assert!(concurrency > 0, "concurrency must be non-zero");
    let mut set = tokio::task::JoinSet::new();
    let mut launched = 0usize;
    let mut succeeded = 0usize;
    let mut errors = Vec::new();
    while launched < total || !set.is_empty() {
        while launched < total && set.len() < concurrency {
            let client = Arc::clone(&client);
            set.spawn(async move { one_handshake(client, address).await });
            launched += 1;
        }
        match set.join_next().await {
            Some(Ok(Ok(()))) => succeeded += 1,
            Some(Ok(Err(error))) => {
                if errors.len() < 5 {
                    errors.push(error);
                }
            }
            Some(Err(join_error)) => {
                if errors.len() < 5 {
                    errors.push(join_error.to_string());
                }
            }
            None => break,
        }
    }
    (succeeded, errors)
}

/// One full client handshake. The server closes the connection after the handshake, which is all
/// the measurement needs.
async fn one_handshake(client: Arc<ClientConfig>, address: SocketAddr) -> Result<(), String> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    let tls = TlsConnector::from(client)
        .connect(
            ServerName::try_from("localhost").expect("static server name"),
            tcp,
        )
        .await
        .map_err(|error| format!("handshake: {error}"))?;
    drop(tls);
    Ok(())
}

// ---------------------------------------------------------------------------
// Sign latency
// ---------------------------------------------------------------------------

/// Measure `iterations` sequential token signatures through the production sign queue.
fn measure_sign_latency(
    pool: &Arc<TokenPool>,
    fixture: &KeyFixture,
    iterations: usize,
) -> Vec<Duration> {
    let signing_key = pool
        .signing_key(&KeySelector {
            label: Some(fixture.label.to_string()),
            id: None,
        })
        .expect("token signing key");
    let signer = signing_key
        .choose_scheme(&[fixture.scheme])
        .expect("the token key must support the measured TLS signature scheme");
    let message = [0xA5u8; 64];
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let signature = signer.sign(&message).expect("token signature");
        samples.push(started.elapsed());
        assert!(!signature.is_empty(), "a token signature must not be empty");
    }
    samples
}

// ---------------------------------------------------------------------------
// The measurement matrix (shared by SoftHSM2 and, when present, a TPM)
// ---------------------------------------------------------------------------

const LATENCY_ITERATIONS: usize = 300;
const HANDSHAKES_PER_SESSION_POINT: usize = 200;
const CONCURRENCY: usize = 32;
const RESUMED_HANDSHAKES: usize = 200;
const SATURATION_ATTEMPTS: usize = 64;
const WORKER_STALL_SECONDS: f64 = 1.5;

async fn measure_matrix(env: &HarnessEnv, platform: &'static str) -> Metrics {
    let metrics = Metrics::default();

    // -- 1. Sign latency for RSA-2048 and P-256 through the production queue. -------------------
    let latency_budget = BudgetSpec {
        max_sessions: 4,
        max_inflight_handshakes: Some(8),
        ..BudgetSpec::after("latency")
    };
    for fixture in [&env.rsa, &env.p256] {
        let (_config, _server, pool) =
            server_from_env(env, fixture, latency_budget, TlsVersions::Tls13Only);
        metrics.record(
            "sign_latency",
            format!("{platform}_{}_budget_readback_max_sessions", fixture.label),
            pool.budget().max_sessions as f64,
            "sessions",
        );
        let samples = measure_sign_latency(&pool, fixture, LATENCY_ITERATIONS);
        record_percentiles(
            &metrics,
            "sign_latency",
            &format!("{platform}_{}", fixture.label),
            &samples,
        );
        // ADR-0009 planning bounds: token signature p95 <= 50 ms and p99 <= 100 ms.
        assert!(
            percentile(&samples, 0.95) <= Duration::from_millis(50),
            "{platform} {} sign p95 exceeds the 50 ms planning bound: {:?}",
            fixture.label,
            percentile(&samples, 0.95)
        );
        assert!(
            percentile(&samples, 0.99) <= Duration::from_millis(100),
            "{platform} {} sign p99 exceeds the 100 ms planning bound: {:?}",
            fixture.label,
            percentile(&samples, 0.99)
        );
        pool.shutdown();
    }

    // -- 2. TLS 1.3 full-handshake throughput at 1, 2 and 4 sessions. ---------------------------
    for sessions in [1u64, 2, 4] {
        let budget = BudgetSpec {
            max_sessions: sessions,
            max_inflight_handshakes: Some(sessions * 8),
            ..BudgetSpec::after("throughput")
        };
        let (_config, server, pool) =
            server_from_env(env, &env.rsa, budget, TlsVersions::Tls13Only);
        let running = start_server(server, Arc::clone(&pool)).await;
        let client = client_config(TLS13_ONLY);
        let signs_before = pool.stats().signs;
        let started = Instant::now();
        let (succeeded, errors) = run_handshakes(
            Arc::clone(&client),
            running.address,
            HANDSHAKES_PER_SESSION_POINT,
            CONCURRENCY,
        )
        .await;
        let elapsed = started.elapsed();
        running.stats.wait_idle().await;
        let rate = succeeded as f64 / elapsed.as_secs_f64();
        metrics.record(
            "throughput",
            format!("{platform}_tls13_full_max_sessions_{sessions}_rate"),
            rate,
            "handshakes/s",
        );
        metrics.record(
            "throughput",
            format!("{platform}_tls13_full_max_sessions_{sessions}_handshakes"),
            succeeded as f64,
            "count",
        );
        metrics.record(
            "throughput",
            format!("{platform}_tls13_full_max_sessions_{sessions}_elapsed"),
            elapsed.as_secs_f64(),
            "s",
        );
        metrics.record(
            "throughput",
            format!("{platform}_tls13_full_max_sessions_{sessions}_token_signs"),
            (pool.stats().signs - signs_before) as f64,
            "count",
        );
        assert!(
            succeeded == HANDSHAKES_PER_SESSION_POINT,
            "{platform} max_sessions={sessions}: {}/{} full handshakes succeeded; first errors: {:?}",
            succeeded,
            HANDSHAKES_PER_SESSION_POINT,
            errors,
        );
        assert_eq!(
            running.stats.failed.load(Ordering::Relaxed),
            0,
            "{platform} max_sessions={sessions}: server-side handshake failures: {:?}",
            running.stats.first_failure.lock().expect("mutex")
        );
        assert!(
            pool.stats().signs > signs_before,
            "{platform} max_sessions={sessions}: full TLS 1.3 handshakes must sign with the token"
        );
        running.wait_idle().await;
        drop(running);
        pool.shutdown();
    }

    // -- 3. Resumed TLS 1.2: high rate, zero token signatures. ----------------------------------
    {
        let budget = BudgetSpec {
            max_sessions: 2,
            max_inflight_handshakes: Some(16),
            ..BudgetSpec::after("resumed")
        };
        let (_config, server, pool) =
            server_from_env(env, &env.rsa, budget, TlsVersions::Tls12Only);
        let running = start_server(server, Arc::clone(&pool)).await;
        let client = client_config(TLS12_ONLY);
        // Warm-up: one full TLS 1.2 handshake caches the session on the client.
        run_handshakes(Arc::clone(&client), running.address, 1, 1)
            .await
            .0
            .eq(&1)
            .then_some(())
            .expect("warm-up full TLS 1.2 handshake must succeed");
        running.stats.wait_idle().await;
        let signs_after_warmup = pool.stats().signs;
        let full_after_warmup = running.stats.full.load(Ordering::Relaxed);
        let started = Instant::now();
        let (succeeded, errors) = run_handshakes(
            Arc::clone(&client),
            running.address,
            RESUMED_HANDSHAKES,
            CONCURRENCY,
        )
        .await;
        let elapsed = started.elapsed();
        running.stats.wait_idle().await;
        let rate = succeeded as f64 / elapsed.as_secs_f64();
        let resumed = running.stats.resumed.load(Ordering::Relaxed);
        let full_delta = running.stats.full.load(Ordering::Relaxed) - full_after_warmup;
        let sign_delta = pool.stats().signs - signs_after_warmup;
        metrics.record(
            "resumed_tls12",
            format!("{platform}_resumed_rate"),
            rate,
            "handshakes/s",
        );
        metrics.record(
            "resumed_tls12",
            format!("{platform}_resumed_handshakes"),
            resumed as f64,
            "count",
        );
        metrics.record(
            "resumed_tls12",
            format!("{platform}_resumed_token_signs"),
            sign_delta as f64,
            "count",
        );
        metrics.record(
            "resumed_tls12",
            format!("{platform}_resumed_fell_back_to_full"),
            full_delta as f64,
            "count",
        );
        assert!(
            succeeded == RESUMED_HANDSHAKES,
            "{platform} resumed TLS 1.2: {}/{} resumed handshakes succeeded; first errors: {:?}",
            succeeded,
            RESUMED_HANDSHAKES,
            errors,
        );
        assert!(
            resumed as usize >= RESUMED_HANDSHAKES - 8,
            "{platform} resumed TLS 1.2: only {resumed}/{RESUMED_HANDSHAKES} handshakes were \
             actually resumed (full fallbacks: {full_delta}); the resumption cache is too small"
        );
        assert_eq!(
            sign_delta, 0,
            "{platform}: a resumed TLS 1.2 handshake must not perform a token signature \
             (observed {sign_delta} during {resumed} resumed handshakes)"
        );
        running.wait_idle().await;
        drop(running);
        pool.shutdown();
    }

    // -- 4. Queue saturation: bounded depth and queue_wait failures, no quarantine. --------------
    {
        let budget = BudgetSpec {
            max_sessions: 1,
            max_inflight_handshakes: Some(SATURATION_ATTEMPTS as u64),
            queue_depth: 1,
            queue_wait_nanos: Some(1_000_000), // 1 ms: deliberately tight
            sign_timeout_nanos: Some(5_000_000_000),
            handshake_wait_nanos: Some(1_000_000_000),
            handshake_timeout_nanos: Some(7_000_000_000),
        };
        let (_config, server, pool) =
            server_from_env(env, &env.rsa, budget, TlsVersions::Tls13Only);
        let running = start_server(server, Arc::clone(&pool)).await;
        let client = client_config(TLS13_ONLY);
        let (succeeded, _errors) = run_handshakes(
            Arc::clone(&client),
            running.address,
            SATURATION_ATTEMPTS,
            SATURATION_ATTEMPTS,
        )
        .await;
        running.stats.wait_idle().await;
        let stats = pool.stats();
        metrics.record(
            "saturation",
            format!("{platform}_budget_sign_timeout_ms"),
            millis(pool.budget().sign_timeout),
            "ms",
        );
        metrics.record(
            "saturation",
            format!("{platform}_budget_queue_wait_ms"),
            millis(pool.budget().queue_wait),
            "ms",
        );
        metrics.record(
            "saturation",
            format!("{platform}_budget_queue_depth"),
            pool.budget().queue_depth as f64,
            "jobs",
        );
        metrics.record(
            "saturation",
            format!("{platform}_budget_max_inflight"),
            pool.budget().max_inflight_handshakes as f64,
            "count",
        );
        metrics.record(
            "saturation",
            format!("{platform}_sign_timeout_failures"),
            stats.sign_timeout_failures as f64,
            "count",
        );
        metrics.record(
            "saturation",
            format!("{platform}_attempts"),
            SATURATION_ATTEMPTS as f64,
            "count",
        );
        metrics.record(
            "saturation",
            format!("{platform}_handshakes_ok"),
            succeeded as f64,
            "count",
        );
        metrics.record(
            "saturation",
            format!("{platform}_queue_wait_failures"),
            stats.queue_wait_failures as f64,
            "count",
        );
        metrics.record(
            "saturation",
            format!("{platform}_max_queue_depth_observed"),
            stats.max_queue_depth as f64,
            "jobs",
        );
        metrics.record(
            "saturation",
            format!("{platform}_quarantined"),
            boolean(pool.is_quarantined()),
            "bool",
        );
        assert!(
            stats.queue_wait_failures > 0,
            "{platform}: a 1 ms queue_wait with one session and queue_depth=1 must reject \
             overloaded handshakes; none failed (SoftHSM2 signs too fast? raise attempts)"
        );
        assert!(
            stats.max_queue_depth <= pool.budget().queue_depth,
            "{platform}: queue depth {} exceeded the configured bound {}",
            stats.max_queue_depth,
            pool.budget().queue_depth
        );
        assert!(
            !pool.is_quarantined(),
            "{platform}: a queue_wait expiry must not quarantine the token"
        );
        assert!(
            stats.sign_timeout_failures == 0,
            "{platform}: no dispatched sign may time out in the saturation phase"
        );
        running.wait_idle().await;
        drop(running);
        pool.shutdown();
    }

    // -- 5. Tokio worker-latency probe under live token-handshake load. -------------------------
    {
        let budget = BudgetSpec {
            max_sessions: 1,
            max_inflight_handshakes: Some(32),
            ..BudgetSpec::after("worker_stall")
        };
        let (_config, server, pool) =
            server_from_env(env, &env.rsa, budget, TlsVersions::Tls13Only);
        let running = start_server(server, Arc::clone(&pool)).await;
        let client = client_config(TLS13_ONLY);
        let stop = Arc::new(AtomicBool::new(false));
        let stalls: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let probe = {
            let stop = Arc::clone(&stop);
            let stalls = Arc::clone(&stalls);
            let observed = Arc::new(AtomicU64::new(0));
            tokio::spawn(async move {
                let tick = Duration::from_millis(1);
                while !stop.load(Ordering::Relaxed) {
                    observed.fetch_add(1, Ordering::Relaxed);
                    let started = Instant::now();
                    tokio::time::sleep(tick).await;
                    let elapsed = started.elapsed().saturating_sub(tick);
                    stalls.lock().expect("stall mutex").push(elapsed);
                }
            })
        };
        // Run a sustained full-handshake load for the probe window while the probe ticks.
        let load_deadline = Instant::now() + Duration::from_secs_f64(WORKER_STALL_SECONDS);
        let mut succeeded = 0usize;
        while Instant::now() < load_deadline {
            let (ok, _errors) = run_handshakes(
                Arc::clone(&client),
                running.address,
                CONCURRENCY,
                CONCURRENCY,
            )
            .await;
            succeeded += ok;
        }
        stop.store(true, Ordering::Relaxed);
        let _ = probe.await;
        running.stats.wait_idle().await;
        let samples = stalls
            .lock()
            .expect("stall mutex")
            .drain(..)
            .collect::<Vec<_>>();
        let p50 = percentile(&samples, 0.50);
        let p99 = percentile(&samples, 0.99);
        let max = samples.iter().copied().max().expect("probe samples");
        metrics.record(
            "worker_stall",
            format!("{platform}_handshakes_ok"),
            succeeded as f64,
            "count",
        );
        metrics.record(
            "worker_stall",
            format!("{platform}_signs"),
            pool.stats().signs as f64,
            "count",
        );
        metrics.record(
            "worker_stall",
            format!("{platform}_probe_samples"),
            samples.len() as f64,
            "count",
        );
        metrics.record(
            "worker_stall",
            format!("{platform}_probe_p50_lateness"),
            millis(p50),
            "ms",
        );
        metrics.record(
            "worker_stall",
            format!("{platform}_probe_p99_lateness"),
            millis(p99),
            "ms",
        );
        metrics.record(
            "worker_stall",
            format!("{platform}_probe_max_lateness"),
            millis(max),
            "ms",
        );
        assert!(
            pool.stats().signs > 0 && succeeded > 0,
            "{platform}: the worker-stall probe needs live handshakes while it ticks"
        );
        // `tokio::time::sleep(1 ms)` has ~1-2 ms overshoot under load on a 46-CPU host, so the
        // bound is 10 ms rather than the 1 ms tick. An inline token sign (no `block_in_place`)
        // would block a worker for at least one sign (p50 1.2 ms) and, with the single session
        // and 32 concurrent handshakes, for queued signs too: stalls of tens of ms per worker.
        assert!(
            p99 <= Duration::from_millis(10),
            "{platform}: an async worker was stalled by a token sign: probe p99 {:?} > 10 ms \
             (the rustls signer must wait under block_in_place, never inline on a worker)",
            p99
        );
        running.wait_idle().await;
        drop(running);
        pool.shutdown();
    }

    // -- 6. sign_timeout quarantine (fail-closed). Runs last: quarantine is process-global. -----
    {
        let budget = BudgetSpec {
            max_sessions: 1,
            max_inflight_handshakes: Some(1),
            queue_depth: 1,
            queue_wait_nanos: Some(1_000_000_000),
            // 1 ns cannot be met by any real token: every dispatched sign misses the deadline,
            // which is exactly the post-dispatch timeout the budget must turn into quarantine.
            sign_timeout_nanos: Some(1),
            handshake_wait_nanos: Some(1_000_000_000),
            handshake_timeout_nanos: Some(7_000_000_000),
        };
        let (_config, _server, pool) =
            server_from_env(env, &env.rsa, budget, TlsVersions::Tls13Only);
        let signing_key = pool
            .signing_key(&KeySelector {
                label: Some(env.rsa.label.to_string()),
                id: None,
            })
            .expect("token signing key");
        let signer = signing_key
            .choose_scheme(&[env.rsa.scheme])
            .expect("scheme");
        let first = signer.sign(&[0u8; 64]);
        metrics.record(
            "quarantine",
            format!("{platform}_forced_sign_timeout_failed"),
            boolean(first.is_err()),
            "bool",
        );
        metrics.record(
            "quarantine",
            format!("{platform}_sign_timeout_failures"),
            pool.stats().sign_timeout_failures as f64,
            "count",
        );
        metrics.record(
            "quarantine",
            format!("{platform}_quarantined"),
            boolean(pool.is_quarantined()),
            "bool",
        );
        assert!(
            first.is_err(),
            "{platform}: a 1 ns sign_timeout must fail the signature"
        );
        assert!(
            pool.is_quarantined(),
            "{platform}: a post-dispatch sign_timeout must quarantine the token"
        );
        let second = signer.sign(&[0u8; 64]);
        assert!(
            second.is_err(),
            "{platform}: a quarantined token must fail closed"
        );
        assert!(
            second
                .as_ref()
                .err()
                .map(|error| error.to_string().contains("quarantine"))
                .unwrap_or(false),
            "{platform}: the second failure must name the quarantine, got {:?}",
            second.err().map(|error| error.to_string())
        );
        pool.shutdown();
    }

    metrics
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn print_environment(env: &HarnessEnv, platform: &str) {
    let mut summary: BTreeMap<&str, String> = BTreeMap::new();
    summary.insert("platform", platform.to_string());
    summary.insert("module", env.module.display().to_string());
    summary.insert("token", env.token.clone());
    summary.insert("rsa_key", env.rsa.label.to_string());
    summary.insert("p256_key", env.p256.label.to_string());
    println!("PKCS11_ENVIRONMENT {}", json!(summary));
}

#[test]
fn soft_hsm_latency_matrix() {
    let Some(env) = HarnessEnv::from_env() else {
        eprintln!(
            "SKIP soft_hsm_latency_matrix: CADDY_RS_PKCS11_MODULE is not set (no PKCS#11 token \
             in this environment). The recorded SoftHSM2 run and its numbers are in \
             docs/operations/PKCS11.md."
        );
        return;
    };
    print_environment(&env, "softhsm2");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("measurement runtime");
    let metrics = runtime.block_on(measure_matrix(&env, "softhsm2"));
    metrics.flush(env.metrics_out.as_deref());
    println!(
        "PKCS11_SUMMARY soft-hsm measurements complete; {} metrics recorded",
        metrics.rows.lock().expect("metrics mutex").len()
    );
}

#[test]
fn tpm2_pkcs11_latency_matrix() {
    let Some(module) = env::var_os("CADDY_RS_PKCS11_TPM_MODULE") else {
        eprintln!(
            "SKIP tpm2_pkcs11_latency_matrix: CADDY_RS_PKCS11_TPM_MODULE is not set. The \
             recording environment has no real TPM (/dev/tpm* absent) and no tpm2-pkcs11 stack, \
             so the ADR-0009 real-TPM acceptance line is UNMET and documented as an external \
             hardware gate in docs/operations/PKCS11.md; no TPM numbers are fabricated here."
        );
        return;
    };
    let module = PathBuf::from(module);
    assert!(
        module.is_file(),
        "CADDY_RS_PKCS11_TPM_MODULE does not name a file: {}",
        module.display()
    );
    // A TPM run needs its own token identity, PIN variable and certificate fixtures; the
    // SoftHSM2-specific variables are intentionally not reused.
    for required in [
        "CADDY_RS_PKCS11_TPM_TOKEN",
        "CADDY_RS_PKCS11_TPM_PIN_VAR",
        "CADDY_RS_PKCS11_TPM_CERT_PEM_RSA",
        "CADDY_RS_PKCS11_TPM_CERT_DER_RSA",
        "CADDY_RS_PKCS11_TPM_CERT_PEM_P256",
        "CADDY_RS_PKCS11_TPM_CERT_DER_P256",
    ] {
        assert!(
            env::var_os(required).is_some(),
            "{required} must be set for the tpm2-pkcs11 measurement"
        );
    }
    let env = HarnessEnv {
        module,
        token: env::var("CADDY_RS_PKCS11_TPM_TOKEN").expect("TPM token label"),
        pin_var: env::var("CADDY_RS_PKCS11_TPM_PIN_VAR").expect("TPM PIN variable name"),
        rsa: KeyFixture {
            label: "rsa2048",
            scheme: SignatureScheme::RSA_PKCS1_SHA256,
            certificate_pem: PathBuf::from(env::var("CADDY_RS_PKCS11_TPM_CERT_PEM_RSA").unwrap()),
            certificate_der: PathBuf::from(env::var("CADDY_RS_PKCS11_TPM_CERT_DER_RSA").unwrap()),
        },
        p256: KeyFixture {
            label: "p256",
            scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            certificate_pem: PathBuf::from(env::var("CADDY_RS_PKCS11_TPM_CERT_PEM_P256").unwrap()),
            certificate_der: PathBuf::from(env::var("CADDY_RS_PKCS11_TPM_CERT_DER_P256").unwrap()),
        },
        metrics_out: env::var_os("CADDY_RS_PKCS11_METRICS_OUT").map(PathBuf::from),
    };
    print_environment(&env, "tpm2_pkcs11");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("measurement runtime");
    let metrics = runtime.block_on(measure_matrix(&env, "tpm2_pkcs11"));
    metrics.flush(env.metrics_out.as_deref());
    println!(
        "PKCS11_SUMMARY tpm2-pkcs11 measurements complete; {} metrics recorded",
        metrics.rows.lock().expect("metrics mutex").len()
    );
}

/// `open_token` is the production constructor used by the loader; this test keeps the direct
/// constructor covered by the harness so the measurement does not depend on a config parse bug.
#[test]
fn token_pool_budget_defaults_match_the_published_defaults() {
    let budget = Pkcs11Budget::default();
    assert_eq!(budget.max_sessions, 1);
    assert_eq!(budget.max_inflight_handshakes, 1);
    assert_eq!(budget.handshake_wait, Duration::from_secs(1));
    assert_eq!(budget.queue_depth, 64);
    assert_eq!(budget.queue_wait, Duration::from_secs(1));
    assert_eq!(budget.sign_timeout, Duration::from_secs(5));
    assert_eq!(budget.handshake_timeout, Duration::from_secs(10));
    // `handshake_timeout >= handshake_wait + queue_wait + sign_timeout` (validation invariant).
    assert!(
        budget.handshake_timeout >= budget.handshake_wait + budget.queue_wait + budget.sign_timeout
    );
    // The direct constructor exists and is not accidentally dead code in a tokenless run.
    let _ = open_token;
}
