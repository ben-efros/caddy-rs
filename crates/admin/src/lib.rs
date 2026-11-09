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
//! | `GET /config/` | Current configuration as JSON (`{}` when no generation is active), strong ETag, `If-None-Match` 304 |
//! | `GET /config/<path>` | JSON traversal by object key or array index, with an ETag for that subtree |
//! | `POST`/`PUT`/`PATCH`/`DELETE /config/<path>` | Partial configuration update with validation and rollback |
//! | `GET /id/<id>` | Object (route) addressed by its `@id`, including nested subroutes |
//! | `POST`/`PUT`/`PATCH`/`DELETE /id/<id>[/<path>]` | Partial update addressed by `@id` |
//! | `POST /load` | Validate, provision, and atomically activate a configuration |
//! | `POST /stop` | Deactivate the running configuration; in the CLI `run` process this terminates the process, like Caddy |
//! | `GET /metrics` | Prometheus text format (v0.0.4) rendered from the shared [`MetricsRegistry`]; empty until the runtime populates it |
//! | `GET /debug/pprof/` (+ `cmdline`/`profile`/`symbol`/`trace`) | Caddy registers Go pprof debugging; caddy-rs answers a located, documented `501` (T-ADMIN-022, DIV-0006) |
//! | `GET /debug/vars` | Caddy registers Go expvar; caddy-rs answers a located, documented `501` (T-ADMIN-022, DIV-0006) |
//! | `GET /pki/ca/<id>` | Caddy-compatible metadata for a provisioned local CA (`caInfo` JSON) |
//! | `GET /pki/ca/<id>/certificates` | PEM certificate chain: intermediate(s) then root |
//! | `GET /pki/ca/<id>/certificates/<name>` | One PEM file from the CA directory (`root.crt`/`intermediate.crt`, caddy-rs extension) |
//! | `GET /reverse_proxy/upstreams` | Configured `reverse_proxy` upstreams in Caddy's status shape, with live counters supplied by the server runtime's [`UpstreamStatusSource`] |
//! | `GET /runtime/inventory` | caddy-rs extension (not a Caddy endpoint): generation, listeners, certificates, upstream counters and health-check schedulers; read-only, explicit `snapshot.available`/`stale` (DIV-0018) |
//! | `POST /adapt` | Adapt a Caddyfile (selected by `Content-Type`, like Caddy) or a `{config, adapter, wrap}` JSON object to Caddy JSON |
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
//! with field selection, sampling and redaction primitives. [`sink`] turns those records into
//! bytes: a validated [`AccessLogEncoder`] (redaction + field selection), a cloneable
//! [`AccessLogSink`] writing to stderr/stdout/a file/discard with buffering, explicit
//! flush/close and located errors, and sampling applied at emission.
//!
//! [`recorder`] is the runtime seam for metrics: a [`RequestRecorder`] observer API (shared
//! handle, no-op implementation, RAII in-flight guards) that forwards request/proxy observations
//! to [`HttpMetrics`], plus [`CertificateMetrics`] hooks for the TLS renewal work. The server
//! runtime stores one recorder and clones it per task; see the module docs for the wiring recipe.
//!
//! [`pki`] exposes the local certificate authority material that the server's automatic HTTPS
//! persisted under `<data-dir>/pki/authorities/<id>/` through read-only admin endpoints. It never
//! provisions or repairs a CA: a missing CA is a located 404 (Caddy lazily provisions the default
//! `local` CA on `/pki` reads; this build deliberately does not).
//!
//! [`logging_config`] maps Caddy's `logging.logs[]` JSON (writer, encoder, level, sampling,
//! include/exclude and the supported encoder filter subset) to validated
//! [`AccessLogSinkConfig`] targets and builds the corresponding sinks. Unsupported writers,
//! encoders and filters fail loudly with located errors and a tracking id instead of being
//! silently ignored.
//!
//! ## Partial updates
//!
//! The resulting *full* configuration is decoded, `@id`-indexed (duplicate ids are rejected with
//! both locations), validated, and only then swapped in atomically. A rejected update leaves the
//! previous generation active; the store's compare-before-swap makes rollback automatic.
//!
//! Documented simplifications:
//!
//! - JSON response bodies (including errors) are terminated with a newline like Caddy's
//!   `json.Encoder`, so bodies and ETag hashes match byte-for-byte.
//! - A mutation that leaves the configuration unchanged is short-circuited: `200 OK` with an empty
//!   body and no new generation. `Cache-Control: must-revalidate` forces the reload, exactly like
//!   Caddy. `POST /load` with an identical config follows the same rule.
//! - Malformed JSON request bodies on config mutations return `500` with a
//!   `decoding request body: ...` message (Caddy returns these as plain, non-`APIError` errors and
//!   the oracle compares admin error responses by status + `{"error": ...}` shape, not wording;
//!   the message text itself is covered by unit tests and DIV-0048).
//!   Config traversal errors (`invalid traversal path`, invalid/out-of-range array indexes) return
//!   `400` with Caddy's message; a missing *leaf* config key reads as JSON `null` with `200`,
//!   matching Caddy (`GET /config/<missing>` is no longer a 404).
//! - ETags and `If-Match` are implemented with Caddy's strong-ETag format
//!   (`"<config path> <xxhash64 hex>"`, same xxhash64 algorithm) and its 400/412 semantics.
//!   Differences from Caddy v2.11.7: Caddy ignores `If-None-Match` entirely, while
//!   caddy-rs serves `304` on a matching config read and `412` on a conditional write
//!   (documented extension); no `Last-Modified` is sent (Caddy sends none either). Config
//!   responses are Go-`encoding/json` compatible (compact, recursively sorted keys, trailing
//!   newline), so the oracle verifies identical bodies, ETags and content-length for the scenario
//!   configs; a config normalized differently by the two implementations could still hash
//!   differently (T-ADMIN-036 verifies the oracle scenario corpus).
//! - `GET /reverse_proxy/upstreams` reports the configured upstream addresses, de-duplicated and
//!   sorted, in Caddy's `[{address,num_requests,fails}]` shape. The server runtime registers an
//!   [`UpstreamStatusSource`] via [`AdminApi::with_upstream_status_source`] and supplies live
//!   `num_requests`/`fails` counters; without a source the counters are `0`. Dynamic upstream
//!   sources are not modelled and the counter semantics are cumulative rather than Caddy's
//!   in-flight/expiring values (DIV-0089).
//! - `POST /adapt` follows Caddy's `Content-Type`-selected adapter semantics; the additional
//!   `{config, adapter, wrap}` JSON request form (with `wrap:false` returning the raw adapted JSON)
//!   is a caddy-rs extension. Adapter warnings are rendered as Caddy-shaped
//!   `[{"message": "..."}]` objects (the caddy-rs adapter only produces messages).
//! - `POST /config/` replaces the whole configuration; `DELETE /config/` unloads it (Caddy
//!   reaches the same state through `run(nil)` via its `rawCfg` wrapper).
//! - `POST /stop` follows Caddy's `handleStop`/`exitProcess`: in the CLI `run` process it
//!   terminates the process asynchronously after the `200 OK` response (the shutdown runs on an OS
//!   thread so a stuck runtime cannot leave the process alive). Embedded uses and unit tests keep
//!   the library behaviour of unloading the generation only; override with
//!   [`AdminApi::with_process_exit_on_stop`].
//! - Origin/host enforcement is evaluated from the active generation on each request; the server
//!   crate may instead pass the startup policy with [`AdminApi::with_origin_policy`]. Caddy's
//!   DNS-rebinding `Host` check is implemented for non-wildcard TCP admin listeners. CORS
//!   responses echo `Access-Control-Allow-Origin` and OPTIONS preflights add
//!   `Access-Control-Allow-Methods`/`Headers`/`Credentials`; like Caddy v2.11.7 no `Vary` header is
//!   emitted. OPTIONS on `/metrics` renders metrics (Caddy ignores the method), OPTIONS on config
//!   paths returns Caddy's `method OPTIONS not allowed`, other method-checked endpoints return
//!   `method not allowed`, and `/pki` 307-redirects to `/pki/`.
//! - Paths are used as the transport transmits them; percent-encoded segments are not decoded
//!   (Caddy's `net/url` decodes `URL.Path` before dispatch). The server crate passes the raw
//!   request path, so `@id` values and object keys containing reserved characters need literal
//!   segments.
//! - `GET /id/<id>` returns `404` for unknown ids as required by the admin contract.
//! - Caddy's admin mux always registers the Go debugging endpoints `/debug/pprof/` (and its
//!   sub-handlers) and `/debug/vars`; caddy-rs has no Go runtime to introspect, so they answer with
//!   a located, documented `501 Not Implemented` (T-ADMIN-022, DIV-0006) instead of fabricating
//!   pprof/expvar data. The bare `/debug/pprof` path 307-redirects like Caddy's ServeMux.
//! - Origin policy derives implicit origins from a non-empty `admin.origins`; the shared core
//!   model cannot distinguish `origins: null` (derive) from `origins: []` (allow none), so an
//!   explicit empty list derives the defaults instead of blocking the endpoint.
//! - `/pki` is read-only: it serves the local CA material persisted under
//!   `<data-dir>/pki/authorities/<id>/` but never provisions, repairs or trusts anything. Caddy
//!   lazily provisions the default `local` CA on a `/pki` read; this build returns `404` instead
//!   and the CA must already exist (for example from automatic HTTPS). `caInfo.name` reflects
//!   `apps.pki.certificate_authorities.<id>.name` from the active generation, defaulting to
//!   Caddy's `Caddy Local Authority` (T-ADMIN-033); the data-directory-only CLI commands cannot
//!   know that configuration and fall back to the id. See [`pki`].
//! - Trust-store installation is exposed through [`trust`] and the CLI `trust` verb (T-ADMIN-033):
//!   the platform store plus discovered NSS/Firefox databases and Java keystores are planned with
//!   their concrete commands, executed idempotently, and every store that cannot be updated is
//!   reported with a loud, located limitation (missing `certutil`/`keytool`/platform tool,
//!   unsupported Windows/other OS). `apps.pki...install_trust: false` is honoured as a no-op when
//!   the CLI is given `--config`; automatic installation during CA provisioning is not implemented
//!   (DIV-0073), so `caddy-rs trust` must be run explicitly.
//! - Metrics rendering, the access-log record/sink model and the Caddy `logging` -> sink mapping
//!   are crate-level primitives (T-ADMIN-020/021/022/025): `/metrics` renders whatever the
//!   runtime records through the [`recorder`] API, and [`logging_config`] turns the active
//!   generation's `logging.logs[]` into ready [`AccessLogSink`] targets. The server runtime still
//!   decides when to build the sinks, emit entries and close them on reload/shutdown. Until it
//!   does, `/metrics` stays empty and access-log output is inert. The rendered `caddy_http_*`
//!   families now match Caddy v2.11.7's names, HELP text, label ordering, Go float presentation and
//!   content type (T-ADMIN-031); the remaining oracle-observed differences are label *values* the
//!   server must supply (route handler name, per-host label, approximate request size) and the
//!   `Server` response header.
//! - Caddy's `apps.http.metrics` and `http.handlers.metrics` JSON shapes are parsed and validated by
//!   [`metrics_config`] with located errors; unsupported behaviour (`otlp`, `per_host`) is rejected
//!   loudly with the tracking id rather than silently dropped. The core config model/validator and
//!   the server runtime must call it (they still reject `apps.http.metrics` as an unknown HTTP-app
//!   field and always record the HTTP series, DIV-0033).
//! - Access-log file rotation (`roll_*` writer options) is not implemented; files are opened in
//!   append mode and rotated externally. See [`sink`] for details.

#![forbid(unsafe_code)]

pub mod access_log;
mod config_path;
pub mod inventory;
pub mod logging_config;
pub mod metrics;
pub mod metrics_config;
mod origin;
pub mod pki;
pub mod recorder;
pub mod sink;
pub mod tracing_config;
pub mod trust;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{drain, Config, Generation, GenerationStore, LifecycleState};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

pub use access_log::{
    AccessLogConfig, AccessLogEntry, AccessLogError, AccessLogField, AccessLogRequest,
    AccessLogSampler, AccessLogTls, AccessLogUpstream, HeaderRedaction, HeaderTarget, LogLevel,
    RedactionPolicy, SamplingConfig, ACCESS_LOG_LOGGER,
};
pub use inventory::{
    InventoryAdminListener, InventoryCertificate, InventoryHealthChecks, InventoryListener,
    RuntimeIntrospectionSource, RuntimeInventorySnapshot,
};
pub use logging_config::{
    AccessLogTarget, BuiltAccessLogSink, LoggingConfig, LoggingConfigError, LOGGING_TRACKING_ID,
};
pub use metrics::{
    HttpMetrics, MetricsError, MetricsRegistry, ProxyObservation, RequestObservation,
    METRICS_CONTENT_TYPE,
};
pub use metrics_config::{
    HttpMetricsConfig, MetricsConfigError, MetricsHandlerConfig, HTTP_METRICS_CONFIG_PATH,
    METRICS_CONFIG_TRACKING_ID, METRICS_HANDLER_CONFIG_PATH,
};
pub use origin::{OriginPolicy, OriginViolation};
pub use pki::{
    authorities_directory, resolve_data_dir, CaMaterial, CaSummary, CertificateInfo, PkiError,
    PkiStore, AUTHORITIES_DIRECTORY, DATA_DIR_ENV, DEFAULT_CA_ID, DEFAULT_CA_NAME,
    DEFAULT_DATA_DIR,
};
pub use recorder::{
    noop_recorder, CertificateMetrics, MetricsRequestRecorder, NoopRequestRecorder,
    ProxyRequestGuard, RequestGuard, RequestRecorder, SharedRequestRecorder,
};
pub use sink::{
    AccessLogEncoder, AccessLogOutput, AccessLogSink, AccessLogSinkConfig, AccessLogSinkStats,
    EmitOutcome, DEFAULT_ACCESS_LOG_BUFFER_BYTES,
};
pub use tracing_config::{
    TracingConfig, TracingConfigError, DEFAULT_TRACING_SPAN_NAME, SERVER_LEVEL_TRACING_NOTE,
    TRACING_HANDLER_CONFIG_PATH, TRACING_TRACKING_ID,
};
pub use trust::{
    discover_java_keystores, discover_nss_databases, TrustEnvironment, TrustPlan, TrustPlatform,
    TrustReport, TrustStatus, TrustStoreKind, TrustTarget, JAVA_KEYSTORE_PASSWORD,
    TRUST_ALIAS_PREFIX,
};

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
    ///
    /// Caddy's admin API encodes JSON with `json.Encoder`, which terminates every document with a
    /// newline; responses and ETag hashes include it so bodies match byte-for-byte.
    pub fn json(status: StatusCode, value: &Value) -> Self {
        let mut body = serde_json::to_vec(value).unwrap_or_else(|error| {
            format!("{{\"error\":\"serialization: {error}\"}}").into_bytes()
        });
        body.push(b'\n');
        let mut response = Self::empty(status);
        response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response.body = Bytes::from(body);
        response
    }

    /// Response with an explicit content type (PEM chains and certificate files).
    pub fn with_content_type(
        status: StatusCode,
        content_type: &'static str,
        body: impl Into<Bytes>,
    ) -> Self {
        let mut response = Self::empty(status);
        response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        );
        response.body = body.into();
        response
    }

    /// Caddy-compatible `APIError` body: `{"error":"<message>"}` with JSON content type.
    pub fn api_error(status: StatusCode, message: impl AsRef<str>) -> Self {
        Self::json(status, &json!({ "error": message.as_ref() }))
    }
}

/// FNV-1a 64 fallback is not used: ETag hashing must match Caddy's xxhash64 so optimistic
/// concurrency headers are stable across implementations of the same config document.

/// The exact bytes Caddy's `json.Encoder` writes for a config document (compact JSON + newline).
/// ETag hashes are computed over these bytes.
fn config_json_body(value: &Value) -> Vec<u8> {
    let mut body = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    body.push(b'\n');
    body
}

/// Caddy's force-reload signal: `Cache-Control: must-revalidate` (exact header value compare).
fn force_reload(request: &AdminRequest) -> bool {
    request
        .headers
        .get(http::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        == Some("must-revalidate")
}

/// Read a config path with Caddy's traversal semantics.
///
/// * a missing object key at the terminal segment reads as `null` (Caddy encodes `v[part]`);
/// * traversing *through* a missing key, a scalar, or a non-canonical/out-of-range array index is
///   a plain error (Caddy returns HTTP 500 for these, not a 404).
fn read_config_value(current: &Value, parts: &[&str]) -> std::result::Result<Value, String> {
    let mut ptr = current;
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        match ptr {
            Value::Object(object) => {
                if last {
                    return Ok(object.get(*part).cloned().unwrap_or(Value::Null));
                }
                match object.get(*part) {
                    Some(Value::Null) | None => {
                        // Caddy discovers the nil value at this segment and errors on the *next*
                        // iteration, so its message includes one more segment.
                        let end = (index + 1).min(parts.len().saturating_sub(1));
                        return Err(format!(
                            "invalid traversal path at: config/{}",
                            parts[..=end].join("/")
                        ));
                    }
                    Some(value) => ptr = value,
                }
            }
            Value::Array(items) => {
                let parsed = part.parse::<i64>().ok();
                let canonical = parsed.filter(|parsed| *parsed >= 0 && *part == parsed.to_string());
                let Some(array_index) = canonical.and_then(|parsed| usize::try_from(parsed).ok())
                else {
                    let reason = if parsed.is_none() {
                        "not a number".to_string()
                    } else {
                        "non-canonical array index".to_string()
                    };
                    return Err(format!(
                        "[/config/{}] invalid array index '{}': {reason}",
                        parts[..=index].join("/"),
                        part
                    ));
                };
                let Some(value) = items.get(array_index) else {
                    return Err(format!(
                        "[/config/{}] array index out of bounds: {}",
                        parts[..=index].join("/"),
                        part
                    ));
                };
                if last {
                    return Ok(value.clone());
                }
                ptr = value;
            }
            _ => {
                return Err(format!(
                    "invalid traversal path at: config/{}",
                    parts[..=index].join("/")
                ))
            }
        }
    }
    Ok(ptr.clone())
}

/// Runtime upstream status for one reverse-proxy address, in Caddy's `/reverse_proxy/upstreams`
/// shape (`num_requests`/`fails` counters).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpstreamStatus {
    /// Upstream dial address (`host:port`).
    pub address: String,
    /// Requests handled by this upstream since it was configured.
    pub num_requests: u64,
    /// Failed requests for this upstream since it was configured.
    pub fails: u64,
}

/// Source of live reverse-proxy upstream counters, supplied by the server runtime.
///
/// The admin crate does not own the proxy pools, so live counters are only available when the
/// server registers a source with [`AdminApi::with_upstream_status_source`]. Without one,
/// `GET /reverse_proxy/upstreams` reports the configured addresses with zero counters.
pub trait UpstreamStatusSource: Send + Sync + std::fmt::Debug {
    /// Current per-address counters (configured addresses should be included even at zero).
    fn upstream_status(&self) -> Vec<UpstreamStatus>;
}

/// 64-bit xxHash (seed 0), the algorithm Caddy uses for config ETags (`admin.go: etagHasher`).
///
/// Implemented locally because the workspace has no cached xxhash crate; the values are validated
/// against the reference vectors in the tests below, and the output format matches Caddy's
/// `"%s %x"` ETag string (`"<config path> <16 hex digits>"`).
fn xxh64(bytes: &[u8]) -> u64 {
    const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

    fn round(accumulator: u64, input: u64) -> u64 {
        accumulator
            .wrapping_add(input.wrapping_mul(PRIME2))
            .rotate_left(31)
            .wrapping_mul(PRIME1)
    }
    fn merge_round(accumulator: u64, value: u64) -> u64 {
        (accumulator ^ round(0, value))
            .wrapping_mul(PRIME1)
            .wrapping_add(PRIME4)
    }

    let length = bytes.len() as u64;
    let mut offset = 0usize;
    let mut hash = if bytes.len() >= 32 {
        let mut v1 = PRIME1.wrapping_add(PRIME2);
        let mut v2 = PRIME2;
        let mut v3 = 0u64;
        let mut v4 = 0u64.wrapping_sub(PRIME1);
        while offset + 32 <= bytes.len() {
            let read = |at: usize| {
                let mut value = [0u8; 8];
                value.copy_from_slice(&bytes[at..at + 8]);
                u64::from_le_bytes(value)
            };
            v1 = round(v1, read(offset));
            v2 = round(v2, read(offset + 8));
            v3 = round(v3, read(offset + 16));
            v4 = round(v4, read(offset + 24));
            offset += 32;
        }
        let mut hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        hash = merge_round(hash, v1);
        hash = merge_round(hash, v2);
        hash = merge_round(hash, v3);
        hash = merge_round(hash, v4);
        hash
    } else {
        PRIME5
    };

    hash = hash.wrapping_add(length);
    while offset + 8 <= bytes.len() {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[offset..offset + 8]);
        let k1 = round(0, u64::from_le_bytes(value));
        hash ^= k1;
        hash = hash
            .rotate_left(27)
            .wrapping_mul(PRIME1)
            .wrapping_add(PRIME4);
        offset += 8;
    }
    if offset + 4 <= bytes.len() {
        let mut value = [0u8; 4];
        value.copy_from_slice(&bytes[offset..offset + 4]);
        hash ^= u64::from(u32::from_le_bytes(value)).wrapping_mul(PRIME1);
        hash = hash
            .rotate_left(23)
            .wrapping_mul(PRIME2)
            .wrapping_add(PRIME3);
        offset += 4;
    }
    while offset < bytes.len() {
        hash ^= u64::from(bytes[offset]).wrapping_mul(PRIME5);
        hash = hash.rotate_left(11).wrapping_mul(PRIME1);
        offset += 1;
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME3);
    hash ^= hash >> 32;
    hash
}

/// A strong ETag in Caddy's exact format: `"<config path> <xxhash64 of the JSON at that path>"`.
fn config_etag(path: &str, body: &[u8]) -> HeaderValue {
    let value = format!("\"{path} {:016x}\"", xxh64(body));
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("\"\""))
}

/// Weak comparison of an `If-None-Match` header against the current strong ETag (RFC 7232 3.2).
fn if_none_match_matches(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Ok(current) = etag.to_str() else {
        return false;
    };
    headers
        .get_all(http::header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|candidate| {
            let candidate = candidate.trim();
            candidate == "*"
                || candidate == current
                || candidate
                    .strip_prefix("W/")
                    .is_some_and(|weak| weak == current)
        })
}

fn warning_json(warnings: &[String]) -> Value {
    // Caddy's `caddyconfig.Warning` marshals as an object; the caddy-rs adapter produces message
    // strings, so map each to `{"message": "..."}` (file/line/directive are absent for this build).
    Value::Array(
        warnings
            .iter()
            .map(|message| json!({ "message": message }))
            .collect(),
    )
}

/// Environment variable by which a hosting process announces the autosave file for configs
/// activated through this API. The CLI `run` command sets it to its effective autosave path
/// (the `--autosave-path` flag or the `$XDG_CONFIG_HOME`-derived default) before the server
/// starts, so admin-driven changes autosave to the file `--resume` reads back, like Caddy.
pub const AUTOSAVE_PATH_ENV: &str = "CADDY_RS_AUTOSAVE_PATH";

/// Admin API logic bound to a generation store.
#[derive(Debug, Clone)]
pub struct AdminApi {
    store: Arc<GenerationStore>,
    drain_timeout: Duration,
    reload_notify: Option<Arc<tokio::sync::Notify>>,
    origin_policy: Option<OriginPolicy>,
    metrics: MetricsRegistry,
    /// Caddy data directory containing `pki/authorities` (admin `/pki` endpoints).
    data_dir: Option<PathBuf>,
    /// Optional live reverse-proxy upstream counters supplied by the server runtime.
    upstream_status_source: Option<Arc<dyn UpstreamStatusSource>>,
    /// Optional live runtime-inventory snapshot supplied by the server runtime
    /// (`GET /runtime/inventory`, caddy-rs extension; DIV-0018).
    introspection_source: Option<Arc<dyn RuntimeIntrospectionSource>>,
    /// Whether `POST /stop` should terminate the process (Caddy's `handleStop` calls
    /// `exitProcess`, so an admin `/stop` always ends the server process).
    ///
    /// Enabled by default when the hosting process looks like the CLI `run` command (it announces
    /// its autosave path through [`AUTOSAVE_PATH_ENV`]); embedded uses and unit tests keep the
    /// library behaviour of unloading the generation only. Override with
    /// [`AdminApi::with_process_exit_on_stop`].
    exit_process_on_stop: bool,
    /// Autosave file for configs activated through this API, mirroring Caddy's autosave of every
    /// non-nil config transition (`caddy.go` `unsyncedDecodeAndRun`, `admin.config.persist`).
    ///
    /// `None` disables admin-driven autosave. The CLI `run` command sets
    /// [`AUTOSAVE_PATH_ENV`] to its effective autosave path before starting the server, so the
    /// admin API of a running `caddy-rs` persists `POST /load`/`/config/...` changes to the very
    /// same file `--resume` reads back. This default keeps standalone/embedded uses (and tests)
    /// write-free unless they opt in.
    autosave_path: Option<PathBuf>,
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
            data_dir: None,
            upstream_status_source: None,
            introspection_source: None,
            // The CLI `run` command is the only process that announces an autosave path; for it,
            // `/stop` must terminate the process like Caddy. Library uses/tests opt out.
            exit_process_on_stop: std::env::var_os(AUTOSAVE_PATH_ENV).is_some(),
            autosave_path: std::env::var_os(AUTOSAVE_PATH_ENV).map(PathBuf::from),
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

    /// Pin the Caddy data directory used by the read-only `/pki` endpoints.
    ///
    /// The server runtime should pass its effective data root (the same directory whose
    /// `pki/authorities/<id>/` holds the internal CA). Without an override the resolution order is
    /// `CADDY_RS_DATA_DIR`, then the active generation's `storage.root`, then `.caddy-rs` (the
    /// server runtime's default).
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Autosave every config this API activates to `path` (atomic write, mode 0600).
    ///
    /// This is the explicit override for [`AUTOSAVE_PATH_ENV`]; the server runtime does not need
    /// it because the CLI announces its effective autosave path through the environment variable.
    /// Override whether `POST /stop` terminates the process (Caddy's `/stop` exits).
    ///
    /// Defaults to true for the CLI `run` process (see [`AdminApi::new`]) and false for embedded
    /// uses; embedders that own the process lifecycle can opt in here.
    pub fn with_process_exit_on_stop(mut self, exit: bool) -> Self {
        self.exit_process_on_stop = exit;
        self
    }

    /// Autosave file for configs activated through this API (see [`AUTOSAVE_PATH_ENV`]).
    pub fn with_autosave_path(mut self, autosave_path: impl Into<PathBuf>) -> Self {
        self.autosave_path = Some(autosave_path.into());
        self
    }

    /// Register the runtime source of live `/reverse_proxy/upstreams` counters.
    ///
    /// The server runtime owns the proxy pools; until it supplies this source the endpoint reports
    /// configured upstreams with `num_requests: 0`/`fails: 0` (documented divergence).
    pub fn with_upstream_status_source(mut self, source: Arc<dyn UpstreamStatusSource>) -> Self {
        self.upstream_status_source = Some(source);
        self
    }

    /// Register the server runtime's runtime-inventory snapshot source for the
    /// `GET /runtime/inventory` caddy-rs extension.
    ///
    /// The server installs a fresh snapshot after every successful apply and clears it on
    /// shutdown; the endpoint only copies the last completed snapshot, so it never blocks a reload.
    pub fn with_runtime_introspection_source(
        mut self,
        source: Arc<dyn RuntimeIntrospectionSource>,
    ) -> Self {
        self.introspection_source = Some(source);
        self
    }

    /// The PKI store for the effective data directory.
    fn pki_store(&self) -> PkiStore {
        let config_storage_root = self.store.current().and_then(|generation| {
            generation
                .config()
                .storage()
                .and_then(|storage| storage.root())
                .map(PathBuf::from)
        });
        PkiStore::new(pki::resolve_data_dir(
            self.data_dir.clone(),
            config_storage_root,
        ))
    }

    /// A shared request recorder backed by this admin API's metrics registry.
    ///
    /// The server runtime stores this handle and calls it for request/proxy lifecycle events; the
    /// same registry is rendered by `GET /metrics`. See [`recorder`] for the full wiring recipe.
    pub fn request_recorder(&self) -> SharedRequestRecorder {
        MetricsRequestRecorder::shared(Arc::new(crate::metrics::HttpMetrics::new(
            self.metrics.clone(),
        )))
    }

    /// Map the *active generation's* `logging` configuration to access-log targets.
    ///
    /// The server runtime calls this when a configuration becomes active (or after `/load`); the
    /// returned [`LoggingConfig`] builds one sink per Caddy log that accepts `http.log.access`.
    /// With no active generation the Caddy default logging configuration is assumed.
    pub fn access_log_config(&self) -> Result<LoggingConfig, LoggingConfigError> {
        match self.store.current() {
            Some(generation) => LoggingConfig::from_config(generation.config()),
            None => LoggingConfig::from_config(&Config::default()),
        }
    }

    /// A certificate-metrics handle backed by this admin API's metrics registry.
    ///
    /// Intended for the TLS certificate/renewal work; the gauge/counter series are rendered by the
    /// same `GET /metrics` endpoint.
    pub fn certificate_metrics(&self) -> CertificateMetrics {
        CertificateMetrics::new(Arc::new(crate::metrics::HttpMetrics::new(
            self.metrics.clone(),
        )))
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

        // Caddy echoes the accepted origin for browser clients and advertises the preflight
        // capabilities on OPTIONS requests (no `Vary` header is sent by Caddy v2.11.7).
        if let Some(origin) = origin {
            if let Ok(value) = HeaderValue::from_str(&origin) {
                response
                    .headers
                    .insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            }
            if request.method == Method::OPTIONS {
                response.headers.insert(
                    http::header::ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("OPTIONS, GET, POST, PUT, PATCH, DELETE"),
                );
                response.headers.insert(
                    http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static("Content-Type, Content-Length, Cache-Control"),
                );
                response.headers.insert(
                    http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
        }
        response
    }

    async fn dispatch(&self, path: &str, request: &AdminRequest) -> AdminResponse {
        let method = request.method.as_str();

        // Caddy's admin mux always registers `/debug/pprof/`, its sub-handlers and `/debug/vars`
        // (admin.go `register debugging endpoints`); they are not gated by configuration, only by
        // where the admin listener is reachable. caddy-rs has no Go runtime to introspect, so the
        // endpoints exist but answer with a located, documented 501 instead of faking data.
        if path == "/debug/pprof" {
            let mut response = AdminResponse::empty(StatusCode::TEMPORARY_REDIRECT);
            response.headers.insert(
                http::header::LOCATION,
                HeaderValue::from_static("/debug/pprof/"),
            );
            return response;
        }
        if path == "/debug/vars" || path == "/debug/pprof/" || path.starts_with("/debug/pprof/") {
            if method != "GET" {
                return AdminResponse::api_error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!("method not allowed: {method}"),
                );
            }
            return AdminResponse::api_error(
                StatusCode::NOT_IMPLEMENTED,
                format!(
                    "debug endpoint `{path}` is not implemented: Caddy serves Go runtime pprof/expvar data                      here, and caddy-rs has no Go runtime to introspect (T-ADMIN-022; DIV-0006)"
                ),
            );
        }

        // Caddy's ServeMux redirects the bare `/pki` path to `/pki/` (307) for every method.
        if path == "/pki" {
            let mut response = AdminResponse::empty(StatusCode::TEMPORARY_REDIRECT);
            response
                .headers
                .insert(http::header::LOCATION, HeaderValue::from_static("/pki/"));
            return response;
        }

        if path == "/config/" || path == "/config" {
            if method != "GET" {
                return self.handle_config_update(path, request);
            }
            let config = self.current_config_or_empty();
            return self.config_read_response("/config/", &config, request);
        }

        if let Some(pointer) = path.strip_prefix("/config/") {
            if method != "GET" {
                return self.handle_config_update(path, request);
            }
            let current = self.current_config_value();
            let parts = config_path::split_path(pointer);
            return match read_config_value(&current, &parts) {
                Ok(value) => self.config_read_response(path, &value, request),
                Err(message) => AdminResponse::api_error(StatusCode::BAD_REQUEST, message),
            };
        }

        if let Some(rest) = path.strip_prefix("/id/") {
            return self.handle_id(rest, request);
        }

        if path == "/pki" || path.starts_with("/pki/") {
            return self.handle_pki(path, request).await;
        }

        match path {
            "/id" | "/id/" => AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                "request path is missing object ID",
            ),
            "/load" => {
                if method != "POST" {
                    return AdminResponse::api_error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method not allowed",
                    );
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
                // Caddy's `Load` short-circuits an identical config unless the client forces a
                // reload with `Cache-Control: must-revalidate`.
                if !force_reload(request) {
                    if let Ok(value) = config.to_value() {
                        if self.config_unchanged(&value) {
                            return self.unchanged_config();
                        }
                    }
                }
                self.commit(config)
            }
            "/stop" => {
                if method != "POST" {
                    return AdminResponse::api_error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method not allowed",
                    );
                }
                self.unload()
            }
            "/metrics" => {
                if method != "GET" && method != "OPTIONS" {
                    return AdminResponse::empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let mut response = AdminResponse::text(StatusCode::OK, self.metrics.render());
                response.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(METRICS_CONTENT_TYPE),
                );
                response
            }
            "/adapt" => self.handle_adapt(request),
            "/reverse_proxy/upstreams" => self.handle_reverse_proxy_upstreams(request),
            "/runtime/inventory" => {
                if method != "GET" {
                    return AdminResponse::api_error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        format!("method not allowed: {method}"),
                    );
                }
                self.runtime_inventory_response()
            }
            "/healthz" => AdminResponse::json(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "active_generation": self.store.current().map(|generation| generation.id()),
                    "lifecycle": self.store.current().map(|generation| generation.state().as_str()),
                }),
            ),
            _ => AdminResponse::text(StatusCode::NOT_FOUND, "404 page not found\n"),
        }
    }

    /// The active configuration as JSON, or `{}` when no generation is active (the same document
    /// `GET /config/` serves and hashes for its ETag).
    fn current_config_or_empty(&self) -> Value {
        let value = self.current_config_value();
        if value.is_null() {
            json!({})
        } else {
            value
        }
    }

    /// Whether `updated` is identical to the active configuration (Caddy's `errSameConfig` check).
    fn config_unchanged(&self, updated: &Value) -> bool {
        let current = self.current_config_value();
        !current.is_null() && *updated == current
    }

    /// Caddy's no-op update response: `200 OK` with an empty body and no new generation.
    fn unchanged_config(&self) -> AdminResponse {
        AdminResponse::empty(StatusCode::OK)
    }

    /// The `(etag path, document)` pair for a config path used by ETags and preconditions.
    ///
    /// `path` is a full admin path (`/config/`, `/config/<...>`); `/id/...` callers pass the
    /// expanded path. `None` means the path does not resolve to a value (missing key, or an
    /// `If-Match` path outside `/config`).
    fn etag_document(&self, path: &str) -> Option<(String, Value)> {
        let path = if path == "/config" { "/config/" } else { path };
        if path == "/config/" {
            return Some(("/config/".to_string(), self.current_config_or_empty()));
        }
        let pointer = path.strip_prefix("/config/")?;
        let current = self.current_config_value();
        let value = navigate(&current, &config_path::split_path(pointer))?;
        Some((path.to_string(), value.clone()))
    }

    /// Build a config read response with Caddy's strong ETag, honouring `If-None-Match`.
    ///
    /// Caddy v2.11.7 sends the ETag but ignores `If-None-Match` (it has no 304 path); serving 304
    /// on a match is a caddy-rs extension. `Last-Modified` is not sent by Caddy and is not added.
    fn config_read_response(
        &self,
        etag_path: &str,
        value: &Value,
        request: &AdminRequest,
    ) -> AdminResponse {
        let body = config_json_body(value);
        let etag = config_etag(etag_path, &body);
        if if_none_match_matches(&request.headers, &etag) {
            let mut response = AdminResponse::empty(StatusCode::NOT_MODIFIED);
            response.headers.insert(http::header::ETAG, etag);
            return response;
        }
        let mut response = AdminResponse::empty(StatusCode::OK);
        response.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response.headers.insert(http::header::ETAG, etag);
        response.body = Bytes::from(body);
        response
    }

    /// Validate `If-Match` (Caddy-compatible 400/412) and `If-None-Match` (caddy-rs extension).
    fn check_write_preconditions(
        &self,
        path: &str,
        request: &AdminRequest,
    ) -> std::result::Result<(), AdminResponse> {
        if let Some(header) = request.headers.get(http::header::IF_MATCH) {
            let header = header.to_str().unwrap_or("");
            let inner = header
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or_else(|| {
                    AdminResponse::api_error(
                        StatusCode::BAD_REQUEST,
                        "malformed If-Match header; expect quoted string",
                    )
                })?;
            let parts: Vec<&str> = inner.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    "malformed If-Match header; expect format \"<path> <hash>\"",
                ));
            }
            let mismatch = || {
                AdminResponse::api_error(
                    StatusCode::PRECONDITION_FAILED,
                    "If-Match header did not match current config hash",
                )
            };
            let (_, value) = self.etag_document(parts[0]).ok_or_else(mismatch)?;
            let body = config_json_body(&value);
            let current_hash = format!("{:016x}", xxh64(&body));
            if current_hash != parts[1] {
                return Err(mismatch());
            }
        }

        if request.headers.contains_key(http::header::IF_NONE_MATCH) {
            let mismatch = || {
                AdminResponse::api_error(
                    StatusCode::PRECONDITION_FAILED,
                    "If-None-Match precondition failed: configuration changed",
                )
            };
            let (etag_path, value) = self.etag_document(path).ok_or_else(mismatch)?;
            let body = config_json_body(&value);
            let etag = config_etag(&etag_path, &body);
            if if_none_match_matches(&request.headers, &etag) {
                return Err(mismatch());
            }
        }
        Ok(())
    }

    /// `POST /adapt`: adapt a Caddyfile (or pass JSON through) using the config adapter.
    ///
    /// Caddy v2.11.7 selects the adapter from the `Content-Type` header
    /// (`text/caddyfile` -> `caddyfile`, `*/json` or empty -> no adaptation) and responds with
    /// `{"warnings":[...],"result":<json>}`. This implementation matches that shape and
    /// additionally accepts a JSON body of the form `{"config":...,"adapter":"caddyfile","wrap":bool}`
    /// as documented in the task (a caddy-rs extension; `wrap:false` returns the adapted JSON
    /// directly). Unsupported adapters and adaptation errors are located 400s.
    fn handle_adapt(&self, request: &AdminRequest) -> AdminResponse {
        if request.method != Method::POST {
            return AdminResponse::api_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        let content_type = request
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let json_media = media_type.is_empty() || media_type.ends_with("/json");

        // caddy-rs extension: explicit `{config, adapter, wrap}` request object.
        if json_media {
            if let Ok(value) = serde_json::from_slice::<Value>(&request.body) {
                if let Some(object) = value.as_object() {
                    if let (Some(config), Some(adapter)) = (
                        object.get("config"),
                        object.get("adapter").and_then(Value::as_str),
                    ) {
                        let wrap = object.get("wrap").and_then(Value::as_bool).unwrap_or(true);
                        return adapt_explicit(config, adapter, wrap);
                    }
                }
            }
        }

        // Caddy's content-type driven behaviour.
        if json_media {
            let result = match serde_json::from_slice::<Value>(&request.body) {
                Ok(result) => result,
                Err(error) => {
                    return AdminResponse::api_error(
                        StatusCode::BAD_REQUEST,
                        format!("invalid config JSON: {error}"),
                    )
                }
            };
            return adapt_response(&result, &[], true);
        }
        let Some((_type, adapter_name)) = media_type.split_once('/') else {
            return AdminResponse::api_error(StatusCode::BAD_REQUEST, "malformed Content-Type");
        };
        let result = match adapter_name {
            "caddyfile" => {
                let Ok(text) = std::str::from_utf8(&request.body) else {
                    return AdminResponse::api_error(
                        StatusCode::BAD_REQUEST,
                        "adapting config using caddyfile adapter: input is not valid UTF-8",
                    );
                };
                match caddy_rs_config::adapt(text) {
                    Ok(adapted) => adapt_response(&adapted.config, &adapted.warnings, true),
                    Err(error) => AdminResponse::api_error(
                        StatusCode::BAD_REQUEST,
                        format!("adapting config using caddyfile adapter: {error}"),
                    ),
                }
            }
            other => AdminResponse::api_error(
                StatusCode::BAD_REQUEST,
                format!("unrecognized config adapter '{other}'"),
            ),
        };
        result
    }

    /// Render the caddy-rs `GET /runtime/inventory` extension snapshot.
    ///
    /// The JSON shape is defined by [`inventory`]: the active generation (id, lifecycle state,
    /// config hash, load time/uptime), the last server-runtime snapshot (admin/listener state,
    /// certificates, health-check schedulers), live per-upstream counters from the registered
    /// [`UpstreamStatusSource`], and an explicit `snapshot.available`/`snapshot.stale` marker so a
    /// missing or mid-reload snapshot is never presented as current. Read-only and non-blocking:
    /// the server runtime installs complete snapshots under a lock.
    fn runtime_inventory_response(&self) -> AdminResponse {
        let current = self.store.current();
        let current_id = current.as_ref().map(|generation| generation.id());
        let snapshot = self
            .introspection_source
            .as_ref()
            .map(|source| source.snapshot());
        let snapshot_available = snapshot.is_some();
        let snapshot = snapshot.unwrap_or_default();
        let stale = snapshot_available && snapshot.generation_id != current_id;
        let now = inventory::unix_seconds(std::time::SystemTime::now()).unwrap_or(0.0);
        let generation = current.as_ref().map(|generation| {
            let loaded_at = inventory::unix_seconds(generation.created_at());
            json!({
                "id": generation.id(),
                "state": generation.state().as_str(),
                "config_hash": self.generation_config_hash(generation),
                "loaded_at": loaded_at,
                "uptime_seconds": loaded_at.map(|loaded| (now - loaded).max(0.0)),
            })
        });
        let admin_listener = snapshot.admin.clone();
        let listeners = snapshot.listeners.clone();
        let certificates = snapshot.certificates.clone();
        let health_checks = snapshot.health_checks.clone();
        let upstreams: Vec<Value> = self
            .upstream_status_source
            .as_ref()
            .map(|source| {
                source
                    .upstream_status()
                    .into_iter()
                    .map(|status| {
                        // The proxy crate does not expose active-health state through its status
                        // source (only cumulative attempts/failures), so `health` is explicit null
                        // rather than a fabricated value (reported hook; see DIV-0018/docs).
                        json!({
                            "address": status.address,
                            "num_requests": status.num_requests,
                            "fails": status.fails,
                            "health": Value::Null,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut notes = vec![
            "upstream `health` is null: the proxy status source exposes counters only (reported hook)"
                .to_string(),
            "certificates: source `managed` = automatic-HTTPS renewal store; `loaded` = apps.tls.certificates"
                .to_string(),
        ];
        if stale {
            notes.push(
                "the active store generation differs from the last applied runtime snapshot                  (apply failed or a reload is in progress); listener/certificate/health data is                  from that snapshot, not from the store generation"
                    .to_string(),
            );
        }
        AdminResponse::json(
            StatusCode::OK,
            &json!({
                "extension": "caddy-rs runtime inventory (caddy-rs extension; Caddy v2.11.7 has no general runtime inventory endpoint; DIV-0018)",
                "generation": generation,
                "runtime": {
                    "applied_generation_id": snapshot.generation_id,
                    "in_sync": snapshot_available && !stale,
                },
                "snapshot": {
                    "available": snapshot_available,
                    "generation_id": snapshot.generation_id,
                    "stale": stale,
                },
                "admin": admin_listener,
                "listeners": listeners,
                "certificates": certificates,
                "upstreams": upstreams,
                "health_checks": health_checks,
                "notes": notes,
            }),
        )
    }

    /// Stable config hash for the inventory (`xxh64` of the serialized Caddy JSON, hex).
    fn generation_config_hash(&self, generation: &Generation) -> Option<String> {
        let bytes = generation.config().to_vec().ok()?;
        Some(format!("{:016x}", xxh64(&bytes)))
    }

    /// `GET /reverse_proxy/upstreams`: Caddy's upstream-status shape for the proxy pools.
    ///
    /// Configured static upstream addresses are always listed. When the server registers an
    /// [`UpstreamStatusSource`] (see [`AdminApi::with_upstream_status_source`]) its live
    /// `num_requests`/`fails` counters and any dynamic/in-flight addresses are merged in;
    /// otherwise counters report 0 (documented residual until the server hooks the proxy pools).
    /// Addresses are de-duplicated like Caddy's global host pool and sorted for determinism.
    fn handle_reverse_proxy_upstreams(&self, request: &AdminRequest) -> AdminResponse {
        if request.method != Method::GET {
            return AdminResponse::api_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        let config = self.current_config_or_empty();
        let mut addresses = BTreeSet::new();
        collect_reverse_proxy_upstreams(&config, &mut addresses);
        let mut statuses: std::collections::BTreeMap<String, UpstreamStatus> = addresses
            .into_iter()
            .map(|address| {
                (
                    address.clone(),
                    UpstreamStatus {
                        address,
                        num_requests: 0,
                        fails: 0,
                    },
                )
            })
            .collect();
        if let Some(source) = &self.upstream_status_source {
            for entry in source.upstream_status() {
                statuses.insert(entry.address.clone(), entry);
            }
        }
        let upstreams: Vec<Value> = statuses
            .into_values()
            .map(|status| {
                json!({
                    "address": status.address,
                    "num_requests": status.num_requests,
                    "fails": status.fails,
                })
            })
            .collect();
        AdminResponse::json(StatusCode::OK, &Value::Array(upstreams))
    }

    /// Handle Caddy's read-only `/pki` endpoints.
    ///
    /// The local CA material is read from the data directory on every request (no caching), never
    /// created or repaired. Origin enforcement and the shared request handling already apply
    /// because this runs inside [`AdminApi::handle`].
    /// The user-facing name Caddy reports for a CA (`caInfo.name`).
    ///
    /// Caddy defaults the name to `Caddy Local Authority` when a configured CA omits `name`; the
    /// admin endpoint reads the active generation so `apps.pki.certificate_authorities.<id>.name`
    /// is reflected without the CA files themselves having to store it.
    fn configured_ca_name(&self, id: &str) -> String {
        self.store
            .current()
            .and_then(|generation| {
                generation
                    .config()
                    .pki()
                    .and_then(|pki| pki.certificate_authorities.as_ref())
                    .and_then(|authorities| authorities.get(id))
                    .and_then(|authority| authority.name.clone())
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| pki::DEFAULT_CA_NAME.to_string())
    }

    async fn handle_pki(&self, path: &str, request: &AdminRequest) -> AdminResponse {
        if request.method != Method::GET {
            return AdminResponse::api_error(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("method not allowed: {}", request.method),
            );
        }
        let Some(rest) = path.strip_prefix("/pki/") else {
            return AdminResponse::api_error(
                StatusCode::NOT_FOUND,
                format!("resource not found: {path}"),
            );
        };
        let store = self.pki_store();
        let segments: Vec<&str> = rest.split('/').collect();
        match segments.as_slice() {
            ["ca", id] if !id.is_empty() => match store.load(id).await {
                Ok(ca) => {
                    let ca = ca.with_name(self.configured_ca_name(id));
                    AdminResponse::json(StatusCode::OK, &ca.info_json())
                }
                Err(error) => pki_error_response(&error, id),
            },
            ["ca", id, "certificates"] if !id.is_empty() => match store.load(id).await {
                Ok(ca) => AdminResponse::with_content_type(
                    StatusCode::OK,
                    "application/pem-certificate-chain",
                    ca.chain_pem(),
                ),
                Err(error) => pki_error_response(&error, id),
            },
            ["ca", id, "certificates", name] if !id.is_empty() => match store.load(id).await {
                Ok(ca) => pki_certificate_response(&ca, name, id, path),
                Err(error) => pki_error_response(&error, id),
            },
            _ => AdminResponse::api_error(
                StatusCode::NOT_FOUND,
                format!("resource not found: {path}"),
            ),
        }
    }

    /// Apply a `POST`/`PUT`/`PATCH`/`DELETE` mutation to the active config path and commit the
    /// resulting full configuration, rolling back on any decode, index, or validation error.
    fn handle_config_update(&self, path: &str, request: &AdminRequest) -> AdminResponse {
        let Some(mutation) = Mutation::from_method(request.method.as_str()) else {
            if request.method == Method::OPTIONS {
                return AdminResponse::api_error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!("method {} not allowed", request.method),
                );
            }
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
                    // Caddy returns this as a plain (non-APIError) error, which the admin
                    // middleware renders as HTTP 500.
                    return AdminResponse::api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("decoding request body: {error}"),
                    );
                }
            }
        };

        // Caddy validates `If-Match` after reading the body and before mutating. `If-None-Match`
        // for mutations is a caddy-rs extension (Caddy ignores it): a match fails with 412.
        if let Err(response) = self.check_write_preconditions(path, request) {
            return response;
        }

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

        // Caddy compares the mutated raw config with the active one and skips the reload (200,
        // empty body, no new generation) unless `Cache-Control: must-revalidate` forces it.
        if !force_reload(request) && self.config_unchanged(&updated) {
            return self.unchanged_config();
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

        let expanded_path = if parts.is_empty() {
            "/config/".to_string()
        } else {
            format!("/config/{}", parts.join("/"))
        };

        if request.method == Method::GET {
            return match read_config_value(&current, &parts) {
                Ok(value) => self.config_read_response(&expanded_path, &value, request),
                Err(message) => AdminResponse::api_error(StatusCode::BAD_REQUEST, message),
            };
        }

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
    ///
    /// Caddy's admin `/stop` calls `exitProcess`, so the CLI process terminates. The library keeps
    /// that opt-in (`exit_process_on_stop`) so embedded hosts and unit tests can unload a
    /// generation without exiting; when enabled, the exit runs asynchronously after a short delay
    /// so the `200 OK` response has time to be written (Caddy likewise shuts its admin listener
    /// down from a goroutine after the handler returns).
    fn unload(&self) -> AdminResponse {
        if let Some(generation) = self.store.stop() {
            let timeout = self.drain_timeout;
            tokio::spawn(async move {
                let _ = drain(&generation, timeout).await;
            });
        }
        self.notify_reload();
        if self.exit_process_on_stop {
            // Tell a systemd `Type=notify` unit before the delayed process exit; best-effort,
            // because a missing/broken NOTIFY_SOCKET must not change /stop semantics.
            let _ = caddy_rs_core::notify::stopping();
            // Use an OS thread, not a tokio task: the runtime may already be shutting down (that is
            // precisely the stuck state this exits from), and a spawned task could be dropped
            // before its timer fires.
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                std::process::exit(0);
            });
        }
        AdminResponse::empty(StatusCode::OK)
    }
}

/// Build the `POST /adapt` response: `{"warnings":[...],"result":...}` (warnings omitted when
/// empty, matching Caddy's `omitempty`), or the raw adapted JSON when `wrap` is false.
fn adapt_response(result: &Value, warnings: &[String], wrap: bool) -> AdminResponse {
    if !wrap {
        return AdminResponse::json(StatusCode::OK, result);
    }
    let mut body = serde_json::Map::new();
    if !warnings.is_empty() {
        body.insert("warnings".to_string(), warning_json(warnings));
    }
    body.insert("result".to_string(), result.clone());
    AdminResponse::json(StatusCode::OK, &Value::Object(body))
}

/// The `{config, adapter, wrap}` extension form of `POST /adapt`.
fn adapt_explicit(config: &Value, adapter: &str, wrap: bool) -> AdminResponse {
    match adapter {
        "json" => adapt_response(config, &[], wrap),
        "caddyfile" => {
            let Some(text) = config.as_str() else {
                return AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    "adapting config using caddyfile adapter: `config` must be a Caddyfile string",
                );
            };
            match caddy_rs_config::adapt(text) {
                Ok(adapted) => adapt_response(&adapted.config, &adapted.warnings, wrap),
                Err(error) => AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    format!("adapting config using caddyfile adapter: {error}"),
                ),
            }
        }
        other => AdminResponse::api_error(
            StatusCode::BAD_REQUEST,
            format!("unrecognized config adapter '{other}'"),
        ),
    }
}

/// Collect configured `reverse_proxy` upstream dial addresses from a config document.
fn collect_reverse_proxy_upstreams(value: &Value, addresses: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("handler").and_then(Value::as_str) == Some("reverse_proxy") {
                if let Some(upstreams) = object.get("upstreams").and_then(Value::as_array) {
                    for upstream in upstreams {
                        match upstream {
                            Value::String(dial) => {
                                addresses.insert(dial.clone());
                            }
                            Value::Object(upstream) => {
                                if let Some(dial) = upstream.get("dial").and_then(Value::as_str) {
                                    addresses.insert(dial.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            for nested in object.values() {
                collect_reverse_proxy_upstreams(nested, addresses);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_reverse_proxy_upstreams(item, addresses);
            }
        }
        _ => {}
    }
}

/// One certificate file from a CA directory (caddy-rs extension endpoint).
fn pki_certificate_response(ca: &CaMaterial, name: &str, id: &str, path: &str) -> AdminResponse {
    let pem = match name {
        "root.crt" | "root.pem" => Some(ca.root_pem().to_string()),
        "intermediate.crt" | "intermediate.pem" => {
            let intermediate = ca.intermediate_pem();
            if intermediate.is_empty() {
                None
            } else {
                Some(intermediate)
            }
        }
        _ => {
            return AdminResponse::api_error(
                StatusCode::NOT_FOUND,
                format!("resource not found: {path}"),
            )
        }
    };
    match pem {
        Some(pem) => {
            AdminResponse::with_content_type(StatusCode::OK, "application/x-pem-file", pem)
        }
        None => AdminResponse::api_error(
            StatusCode::NOT_FOUND,
            format!("CA `{id}` has no intermediate certificate"),
        ),
    }
}

/// Map a [`PkiError`] to a Caddy-compatible API error response.
fn pki_error_response(error: &PkiError, id: &str) -> AdminResponse {
    match error {
        PkiError::NotFound { .. } => AdminResponse::api_error(
            StatusCode::NOT_FOUND,
            // Caddy's exact message for an unconfigured CA id. Caddy would lazy-provision the
            // default `local` CA here; this build is read-only and deliberately does not.
            format!("no certificate authority configured with id: {id}"),
        ),
        PkiError::InvalidCaId { .. } => {
            AdminResponse::api_error(StatusCode::BAD_REQUEST, error.to_string())
        }
        _ => AdminResponse::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to get root and intermediate cert for CA {id}: {error}"),
        ),
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

        // Caddy renders a missing leaf key as JSON `null` with 200 (traversal errors are 500).
        let response = admin
            .handle(request("GET", "/config/apps/missing", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"null\n"));
        assert!(response.headers.contains_key(http::header::ETAG));
        // Traversing *through* a missing key is a located 400, matching Caddy.
        let response = admin
            .handle(request("GET", "/config/apps/missing/deeper", ""))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("invalid traversal path"));
    }

    fn etag_of(response: &AdminResponse) -> String {
        response
            .headers
            .get(http::header::ETAG)
            .expect("response carries an ETag")
            .to_str()
            .unwrap()
            .to_string()
    }

    async fn config_etag_for_path(admin: &AdminApi, path: &str) -> String {
        let response = admin.handle(request("GET", path, "")).await;
        assert_eq!(response.status, StatusCode::OK, "GET {path}");
        etag_of(&response)
    }

    fn with_header(
        mut request: AdminRequest,
        name: http::header::HeaderName,
        value: &str,
    ) -> AdminRequest {
        request
            .headers
            .insert(name, HeaderValue::from_str(value).unwrap());
        request
    }

    #[test]
    fn xxh64_matches_reference_vectors_and_caddy_etag_format() {
        // Vectors from xxHash's reference implementation (validated with `xxh64sum`).
        assert_eq!(xxh64(b""), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"abc"), 0x44bc_2cf5_ad77_0999);
        assert_eq!(xxh64(b"hello"), 0x26c7_827d_889f_6da3);
        assert_eq!(xxh64(b"message digest"), 0x066e_d728_fcee_b3be);
        assert_eq!(
            config_etag("/config/", b"{}").to_str().unwrap(),
            format!("\"/config/ {:016x}\"", xxh64(b"{}"))
        );
    }

    #[tokio::test]
    async fn config_etags_are_strong_and_change_with_the_config() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let etag = etag_of(&response);
        assert!(
            etag.starts_with("\"/config/ ") && etag.ends_with('"'),
            "Caddy ETag shape expected, got {etag}"
        );
        let hash_start = etag.find(' ').expect("ETag has a space") + 1;
        let hash = etag[hash_start..etag.len() - 1].to_string();
        assert_eq!(hash.len(), 16, "16 hex digits expected");
        assert!(hash.chars().all(|character| character.is_ascii_hexdigit()));

        // Unchanged config: identical ETag.
        assert_eq!(config_etag_for_path(&admin, "/config/").await, etag);

        // Subtree ETags carry the requested path and the subtree hash.
        let subtree_etag = config_etag_for_path(&admin, "/config/apps/http").await;
        assert!(
            subtree_etag.starts_with("\"/config/apps/http "),
            "got {subtree_etag}"
        );

        // A config mutation changes the ETag (reload/generation change).
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9090"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        let after = config_etag_for_path(&admin, "/config/").await;
        assert_ne!(after, etag, "ETag must change when the config changes");

        // A GET with the matching If-None-Match is a 304 with no body and the current ETag.
        let conditional = with_header(
            request("GET", "/config/", ""),
            http::header::IF_NONE_MATCH,
            &after,
        );
        let response = admin.handle(conditional).await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
        assert!(response.body.is_empty());
        assert_eq!(etag_of(&response), after);
    }

    #[tokio::test]
    async fn if_match_precondition_protects_config_updates() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let etag = config_etag_for_path(&admin, "/config/").await;

        // Matching If-Match: the update applies.
        let conditional = with_header(
            json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9090"),
            ),
            http::header::IF_MATCH,
            &etag,
        );
        let response = admin.handle(conditional).await;
        assert_eq!(response.status, StatusCode::OK);
        let updated_etag = config_etag_for_path(&admin, "/config/").await;
        assert_ne!(updated_etag, etag);

        // Stale If-Match: 412 with Caddy's exact message, config unchanged.
        let stale = with_header(
            json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9091"),
            ),
            http::header::IF_MATCH,
            &etag,
        );
        let response = admin.handle(stale).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(&response),
            "{\"error\":\"If-Match header did not match current config hash\"}\n"
        );
        assert_eq!(config_etag_for_path(&admin, "/config/").await, updated_etag);

        // Malformed headers: Caddy's 400 messages.
        for (value, expected) in [
            ("abc", "malformed If-Match header; expect quoted string"),
            ("\"abc\"", "malformed If-Match header; expect format"),
        ] {
            let malformed = with_header(
                json_request(
                    "PATCH",
                    "/config/apps/http/servers/srv0/listen/0",
                    json!(":9092"),
                ),
                http::header::IF_MATCH,
                value,
            );
            let response = admin.handle(malformed).await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "header {value}");
            assert!(body_string(&response).contains(expected));
        }

        // A path that does not resolve is a mismatch (Caddy returns 412 for this too).
        let missing = with_header(
            json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9093"),
            ),
            http::header::IF_MATCH,
            "\"/config/nope 0000000000000000\"",
        );
        let response = admin.handle(missing).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert!(body_string(&response).contains("If-Match header did not match"));
    }

    #[tokio::test]
    async fn if_none_match_is_a_documented_caddy_rs_extension() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        // Matching If-None-Match on a read: 304.
        let response = admin
            .handle(with_header(
                request("GET", "/config/apps/http", ""),
                http::header::IF_NONE_MATCH,
                &config_etag_for_path(&admin, "/config/apps/http").await,
            ))
            .await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);

        // Non-matching If-None-Match on a read: normal 200.
        let response = admin
            .handle(with_header(
                request("GET", "/config/", ""),
                http::header::IF_NONE_MATCH,
                "\"/config/ 0000000000000000\"",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);

        // Matching If-None-Match on a write: 412 (Caddy itself ignores the header). The
        // precondition is evaluated against the ETag of the write target path.
        let target_path = "/config/apps/http/servers/srv0/listen/0";
        let target_etag = config_etag_for_path(&admin, target_path).await;
        let conditional = with_header(
            json_request("PATCH", target_path, json!(":9094")),
            http::header::IF_NONE_MATCH,
            &target_etag,
        );
        let response = admin.handle(conditional).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert!(body_string(&response).contains("If-None-Match precondition failed"));

        // Non-matching If-None-Match on a write: applies.
        let conditional = with_header(
            json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9095"),
            ),
            http::header::IF_NONE_MATCH,
            "\"/config/ 0000000000000000\"",
        );
        assert_eq!(admin.handle(conditional).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn unchanged_updates_are_short_circuited_without_a_new_generation() {
        let admin = admin();
        load(&admin, &valid_config()).await;
        let generation_before = admin.store().current().expect("active").id();

        // PATCH with the same value: 200, empty body, no new generation.
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":8080"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty(), "Caddy returns an empty body");
        assert_eq!(
            admin.store().current().expect("active").id(),
            generation_before,
            "unchanged config must not create a generation"
        );

        // POST /load with the same document: also a no-op.
        let response = load(&admin, &valid_config()).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(
            admin.store().current().expect("active").id(),
            generation_before
        );

        // POST /config/ with the same document: also a no-op.
        let response = admin
            .handle(json_request("POST", "/config/", &valid_config()))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            admin.store().current().expect("active").id(),
            generation_before
        );

        // `Cache-Control: must-revalidate` forces the reload even when unchanged.
        let mut forced = json_request(
            "PATCH",
            "/config/apps/http/servers/srv0/listen/0",
            json!(":8080"),
        );
        forced.headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("must-revalidate"),
        );
        let response = admin.handle(forced).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_ne!(
            admin.store().current().expect("active").id(),
            generation_before,
            "must-revalidate must force a new generation"
        );

        // A real change still creates a generation.
        let generation_now = admin.store().current().expect("active").id();
        let response = admin
            .handle(json_request(
                "PATCH",
                "/config/apps/http/servers/srv0/listen/0",
                json!(":9090"),
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_ne!(
            admin.store().current().expect("active").id(),
            generation_now
        );
    }

    #[tokio::test]
    async fn unknown_admin_paths_return_caddys_plain_404() {
        let admin = admin();
        let response = admin.handle(request("GET", "/nope", "")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(body_string(&response), "404 page not found\n");
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    /// Test-only runtime upstream counter source.
    #[derive(Debug)]
    struct StaticUpstreamStatus(Vec<UpstreamStatus>);

    impl UpstreamStatusSource for StaticUpstreamStatus {
        fn upstream_status(&self) -> Vec<UpstreamStatus> {
            self.0.clone()
        }
    }

    fn assert_sorted_object_keys(value: &Value) {
        match value {
            Value::Object(map) => {
                let keys: Vec<&String> = map.keys().collect();
                let mut sorted = keys.clone();
                sorted.sort();
                assert_eq!(
                    keys, sorted,
                    "object keys are not recursively sorted: {value:?}"
                );
                for nested in map.values() {
                    assert_sorted_object_keys(nested);
                }
            }
            Value::Array(items) => items.iter().for_each(assert_sorted_object_keys),
            _ => {}
        }
    }

    #[tokio::test]
    async fn config_read_serialization_matches_go_encoding_json_bytes() {
        // Caddy serves `encoding/json` output: compact, recursively sorted object keys and a
        // trailing newline from `json.Encoder`; the ETag is xxHash64 over exactly those bytes.
        let admin = admin();
        let config = json!({
            "storage": {"module": "file_system", "root": "/var/lib/caddy"},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"@id": "route0", "handle": [
                    {"handler": "static_response", "body": "hello", "status_code": 200}
                ]}]
            }}}},
            "admin": {"listen": "localhost:2019"}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = response.body.to_vec();
        assert!(body.ends_with(b"\n"), "Go json.Encoder newline");
        let parsed: Value = serde_json::from_slice(&body).expect("config JSON");
        assert_sorted_object_keys(&parsed);
        // Byte-for-byte canonical Go encoding: re-serialising the parsed value reproduces the
        // served bytes (modulo the encoder newline).
        let canonical = serde_json::to_vec(&parsed).expect("canonical serialization");
        assert_eq!(&body[..body.len() - 1], canonical.as_slice());
        // The strong ETag is over the exact served bytes; content-length is body.len().
        let expected_etag = config_etag("/config/", &body);
        assert_eq!(
            response.headers.get(http::header::ETAG).unwrap(),
            &expected_etag
        );
        assert_eq!(body.len(), response.body.len());

        // Determinism: an unchanged config read yields identical bytes and ETag.
        let again = admin.handle(request("GET", "/config/", "")).await;
        assert_eq!(again.body, response.body);
        assert_eq!(
            again.headers.get(http::header::ETAG).unwrap(),
            &expected_etag
        );
    }

    #[tokio::test]
    async fn reverse_proxy_upstreams_merges_runtime_counters_when_a_source_is_registered() {
        let admin = admin().with_upstream_status_source(Arc::new(StaticUpstreamStatus(vec![
            UpstreamStatus {
                address: "127.0.0.1:9001".to_string(),
                num_requests: 42,
                fails: 3,
            },
            UpstreamStatus {
                address: "127.0.0.1:9999".to_string(),
                num_requests: 1,
                fails: 0,
            },
        ])));
        let config = json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": ["127.0.0.1:0"],
                "routes": [{"handle": [{"handler": "reverse_proxy", "upstreams": [
                    {"dial": "127.0.0.1:9001"}, {"dial": "127.0.0.1:9002"}
                ]}]}]
            }}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin
            .handle(request("GET", "/reverse_proxy/upstreams", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        let upstreams: Value = serde_json::from_slice(&response.body).unwrap();
        let entries = upstreams.as_array().expect("array");
        assert_eq!(
            entries.len(),
            3,
            "configured + dynamic addresses are merged"
        );
        let by_address = |address: &str| {
            entries
                .iter()
                .find(|entry| entry["address"] == address)
                .cloned()
                .expect("address entry")
        };
        assert_eq!(by_address("127.0.0.1:9001")["num_requests"], 42);
        assert_eq!(by_address("127.0.0.1:9001")["fails"], 3);
        assert_eq!(by_address("127.0.0.1:9002")["num_requests"], 0);
        assert_eq!(
            by_address("127.0.0.1:9999")["num_requests"],
            1,
            "runtime-only (dynamic/in-flight) addresses are included"
        );
    }

    #[tokio::test]
    async fn reverse_proxy_upstreams_reports_configured_addresses() {
        let admin = admin();
        let config = json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": ["127.0.0.1:0"],
                "routes": [
                    {"handle": [{"handler": "reverse_proxy", "upstreams": [
                        {"dial": "127.0.0.1:9001"}, {"dial": "127.0.0.1:9002"}
                    ]}]},
                    {"handle": [{"handler": "reverse_proxy", "upstreams": [
                        {"dial": "127.0.0.1:9001"}
                    ]}]},
                    {"handle": [{"handler": "static_response", "body": "ok"}]}
                ]
            }}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin
            .handle(request("GET", "/reverse_proxy/upstreams", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let upstreams: Value = serde_json::from_slice(&response.body).unwrap();
        let addresses: Vec<&str> = upstreams
            .as_array()
            .expect("upstreams array")
            .iter()
            .map(|entry| entry["address"].as_str().expect("address"))
            .collect();
        assert_eq!(
            addresses,
            vec!["127.0.0.1:9001", "127.0.0.1:9002"],
            "configured upstreams are de-duplicated and sorted"
        );
        for entry in upstreams.as_array().unwrap() {
            assert_eq!(entry["num_requests"], 0);
            assert_eq!(entry["fails"], 0);
        }

        // Caddy returns 405 for non-GET.
        let response = admin
            .handle(request("POST", "/reverse_proxy/upstreams", ""))
            .await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(body_string(&response).contains("method not allowed"));

        // No active config: empty array (not an error).
        admin.handle(request("POST", "/stop", "")).await;
        let response = admin
            .handle(request("GET", "/reverse_proxy/upstreams", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap(),
            json!([])
        );
    }

    #[tokio::test]
    async fn adapt_endpoint_supports_caddy_content_type_and_explicit_shapes() {
        let admin = admin();

        // Caddy-compatible: adapter selected by Content-Type, result wrapped, warnings omitted.
        let mut caddyfile = request("POST", "/adapt", ":8080 {\n\trespond \"ok\"\n}\n");
        caddyfile.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/caddyfile"),
        );
        let response = admin.handle(caddyfile).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let adapted: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(adapted.get("warnings").is_none(), "no warnings expected");
        let result = &adapted["result"];
        assert!(result["apps"]["http"]["servers"].is_object());

        // JSON content type: no adaptation; the document is returned as the result.
        let mut json_request = request("POST", "/adapt", "{\"apps\":{}}");
        json_request.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let response = admin.handle(json_request).await;
        assert_eq!(response.status, StatusCode::OK);
        let adapted: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(adapted["result"], json!({"apps": {}}));

        // caddy-rs extension: {config, adapter, wrap}; wrap:false returns the raw adapted JSON.
        let explicit_body = json!({
            "config": ":8081 {\n\trespond \"ok\"\n}\n",
            "adapter": "caddyfile",
            "wrap": false
        })
        .to_string();
        let mut explicit = request("POST", "/adapt", &explicit_body);
        explicit.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let response = admin.handle(explicit).await;
        assert_eq!(response.status, StatusCode::OK);
        let adapted: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(adapted["apps"]["http"]["servers"].is_object());
        assert!(adapted.get("result").is_none(), "wrap:false is unwrapped");

        // Unknown adapters: located 400s.
        let mut unknown = request("POST", "/adapt", "x");
        unknown.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/nope"),
        );
        let response = admin.handle(unknown).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("unrecognized config adapter 'nope'"));

        let mut malformed = request("POST", "/adapt", "not a caddyfile {");
        malformed.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/caddyfile"),
        );
        let response = admin.handle(malformed).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("adapting config using caddyfile adapter"));

        // Non-POST is 405 like Caddy.
        let response = admin.handle(request("GET", "/adapt", "")).await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
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
    async fn stop_deactivates_the_generation_and_process_exit_is_opt_in() {
        // Unit tests do not announce AUTOSAVE_PATH_ENV, so `/stop` must unload the generation and
        // let the embedding process decide its lifecycle (the CLI `run` process opts in).
        assert!(!admin().exit_process_on_stop);
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
        assert_eq!(response.body, Bytes::from_static(b"{}\n"));
    }

    #[tokio::test]
    async fn access_log_config_maps_the_active_generation_logging_section() {
        let admin = admin();
        let config = json!({
            "logging": {"logs": {"default": {
                "writer": {"output": "discard"},
                "level": "warn"
            }}},
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );
        let mapping = admin.access_log_config().expect("map logging");
        assert_eq!(mapping.targets().len(), 1);
        assert_eq!(mapping.targets()[0].name(), "default");
        assert_eq!(
            mapping.targets()[0].sink_config().level,
            Some(LogLevel::Warn)
        );

        // No active generation: Caddy's implicit default log (stderr, INFO) is assumed.
        admin.handle(request("POST", "/stop", "")).await;
        let mapping = admin.access_log_config().expect("defaults");
        assert_eq!(mapping.targets().len(), 1);
        assert_eq!(mapping.targets()[0].name(), "default");
    }

    #[tokio::test]
    async fn runtime_recorder_and_certificate_metrics_feed_the_metrics_endpoint() {
        let admin = admin();
        load(&admin, &valid_config()).await;

        // The server runtime records through the shared handle; `/metrics` renders the same
        // registry, so a recorded request must be visible on the endpoint.
        let recorder = admin.request_recorder();
        let guard = recorder.request_started("srv0", "route0").expect("start");
        recorder
            .request_finished(&RequestObservation::new(
                "srv0",
                "route0",
                "GET",
                200,
                Duration::from_millis(5),
            ))
            .expect("finish");
        drop(guard);
        admin
            .certificate_metrics()
            .certificate_expiry("acme", "example.com", 3_600.0)
            .expect("certificate expiry");

        let response = admin.handle(request("GET", "/metrics", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = body_string(&response);
        assert!(
            body.contains("caddy_http_requests_total{handler=\"route0\",server=\"srv0\"} 1"),
            "metrics body:\n{body}"
        );
        assert!(
            body.contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 0"),
            "metrics body:\n{body}"
        );
        assert!(
            body.contains(
                "caddy_rs_tls_certificate_expiration_seconds{issuer=\"acme\",subject=\"example.com\"} 3600"
            ),
            "metrics body:\n{body}"
        );
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
        assert_eq!(
            response.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Caddy returns malformed-body decode failures as plain 500 errors"
        );
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = body_string(&response);
        assert!(
            body.ends_with('\n'),
            "JSON admin bodies are newline-terminated"
        );
        let error: Value = serde_json::from_str(&body).expect("Caddy APIError shape");
        assert!(
            error["error"]
                .as_str()
                .expect("string error")
                .starts_with("decoding request body: "),
            "{error}"
        );

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
            Bytes::from_static(b"{}\n")
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

    // -- Debug endpoints (Caddy admin /debug/pprof, /debug/vars) ----------------------------

    #[tokio::test]
    async fn debug_endpoints_are_located_documented_501s_not_fake_data() {
        let admin = admin();
        for path in [
            "/debug/vars",
            "/debug/pprof/",
            "/debug/pprof/cmdline",
            "/debug/pprof/profile",
            "/debug/pprof/symbol",
            "/debug/pprof/trace",
        ] {
            let response = admin.handle(request("GET", path, "")).await;
            assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED, "{path}");
            assert_eq!(
                response
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/json"),
                "{path}"
            );
            let body: Value = serde_json::from_slice(&response.body).expect("APIError JSON");
            let error = body["error"].as_str().expect("error string");
            assert!(error.contains("not implemented"), "{path}: {error}");
            assert!(error.contains("Go runtime"), "{path}: {error}");
            assert!(error.contains("T-ADMIN-022"), "{path}: {error}");
            assert!(error.contains("DIV-0006"), "{path}: {error}");
        }

        // A non-GET request is a method error, matching the endpoints' GET-only contract.
        let response = admin.handle(request("POST", "/debug/vars", "{}")).await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);

        // Caddy's ServeMux redirects the bare pprof path to the tree root.
        let response = admin.handle(request("GET", "/debug/pprof", "")).await;
        assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/debug/pprof/")
        );
    }

    // -- Runtime inventory extension (GET /runtime/inventory) ------------------------------

    #[derive(Debug)]
    struct FakeInventorySource {
        snapshot: RuntimeInventorySnapshot,
    }

    impl RuntimeIntrospectionSource for FakeInventorySource {
        fn snapshot(&self) -> RuntimeInventorySnapshot {
            self.snapshot.clone()
        }
    }

    #[derive(Debug)]
    struct FakeUpstreamSource {
        statuses: Vec<UpstreamStatus>,
    }

    impl UpstreamStatusSource for FakeUpstreamSource {
        fn upstream_status(&self) -> Vec<UpstreamStatus> {
            self.statuses.clone()
        }
    }

    fn inventory_snapshot(generation_id: Option<u64>) -> RuntimeInventorySnapshot {
        RuntimeInventorySnapshot {
            generation_id,
            admin: Some(InventoryAdminListener {
                configured: Some("localhost:2019".to_string()),
                bound: Some("[::1]:2019".to_string()),
            }),
            listeners: vec![InventoryListener {
                server: "srv0".to_string(),
                configured: ":8080".to_string(),
                bound: Some("0.0.0.0:8080".to_string()),
                network: "tcp".to_string(),
                tls: false,
                protocols: vec!["h1".to_string(), "h2".to_string()],
                http3: false,
            }],
            certificates: vec![InventoryCertificate {
                subject: "example.com".to_string(),
                sans: vec!["example.com".to_string(), "www.example.com".to_string()],
                issuer: Some("https://ca.example/acme".to_string()),
                not_after: Some(1_800_000_000.0),
                source: "managed".to_string(),
            }],
            health_checks: vec![InventoryHealthChecks {
                generation: 1,
                checkers: 2,
            }],
        }
    }

    #[tokio::test]
    async fn runtime_inventory_reports_generation_snapshot_upstreams_and_is_read_only() {
        let admin = admin()
            .with_runtime_introspection_source(Arc::new(FakeInventorySource {
                snapshot: inventory_snapshot(Some(1)),
            }))
            .with_upstream_status_source(Arc::new(FakeUpstreamSource {
                statuses: vec![UpstreamStatus {
                    address: "127.0.0.1:9000".to_string(),
                    num_requests: 7,
                    fails: 1,
                }],
            }));
        load(&admin, &valid_config()).await;

        let response = admin.handle(request("GET", "/runtime/inventory", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let value: Value = serde_json::from_slice(&response.body).expect("inventory JSON");
        assert!(value["extension"]
            .as_str()
            .expect("extension marker")
            .contains("DIV-0018"));
        assert_eq!(value["generation"]["id"], 1);
        assert_eq!(value["generation"]["state"], "active");
        let hash = value["generation"]["config_hash"]
            .as_str()
            .expect("config hash");
        assert_eq!(hash.len(), 16, "{hash}");
        assert!(value["generation"]["uptime_seconds"].as_f64().unwrap() >= 0.0);
        assert_eq!(value["snapshot"]["available"], true);
        assert_eq!(value["snapshot"]["generation_id"], 1);
        assert_eq!(value["snapshot"]["stale"], false);
        assert_eq!(value["admin"]["bound"], "[::1]:2019");
        assert_eq!(value["listeners"].as_array().unwrap().len(), 1);
        assert_eq!(value["listeners"][0]["bound"], "0.0.0.0:8080");
        assert_eq!(value["listeners"][0]["protocols"][0], "h1");
        assert_eq!(value["certificates"][0]["subject"], "example.com");
        assert_eq!(value["certificates"][0]["source"], "managed");
        assert_eq!(value["certificates"][0]["not_after"], 1_800_000_000.0);
        assert_eq!(value["upstreams"][0]["address"], "127.0.0.1:9000");
        assert_eq!(value["upstreams"][0]["num_requests"], 7);
        assert!(value["upstreams"][0]["health"].is_null());
        assert_eq!(value["health_checks"][0]["generation"], 1);
        assert_eq!(value["health_checks"][0]["checkers"], 2);

        // Read-only extension: non-GET methods are rejected.
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let response = admin
                .handle(request(method, "/runtime/inventory", "{}"))
                .await;
            assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        }
    }

    #[tokio::test]
    async fn runtime_inventory_with_no_generation_is_explicitly_empty() {
        let admin = admin();
        let value: Value = serde_json::from_slice(
            &admin
                .handle(request("GET", "/runtime/inventory", ""))
                .await
                .body,
        )
        .expect("inventory JSON");
        assert!(value["generation"].is_null());
        assert_eq!(value["snapshot"]["available"], false);
        assert_eq!(value["runtime"]["in_sync"], false);
        assert_eq!(value["listeners"], serde_json::json!([]));
        assert_eq!(value["certificates"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn runtime_inventory_marks_missing_and_stale_snapshots_explicitly() {
        // No server runtime source: the representation must say so instead of fabricating data.
        let plain_admin = admin();
        load(&plain_admin, &valid_config()).await;
        let value: Value = serde_json::from_slice(
            &plain_admin
                .handle(request("GET", "/runtime/inventory", ""))
                .await
                .body,
        )
        .expect("inventory JSON");
        assert_eq!(value["snapshot"]["available"], false);
        assert_eq!(value["snapshot"]["stale"], false);
        assert_eq!(value["listeners"], serde_json::json!([]));
        assert_eq!(value["certificates"], serde_json::json!([]));
        assert_eq!(value["health_checks"], serde_json::json!([]));
        assert_eq!(value["generation"]["id"], 1);

        // A snapshot captured for an older generation is reported as stale, never as current.
        let stale_admin =
            admin().with_runtime_introspection_source(Arc::new(FakeInventorySource {
                snapshot: inventory_snapshot(Some(1)),
            }));
        load(&stale_admin, &valid_config()).await;
        load(&stale_admin, &valid_config().replace(":8080", ":8081")).await;
        let value: Value = serde_json::from_slice(
            &stale_admin
                .handle(request("GET", "/runtime/inventory", ""))
                .await
                .body,
        )
        .expect("inventory JSON");
        assert_eq!(value["generation"]["id"], 2);
        assert_eq!(value["snapshot"]["generation_id"], 1);
        assert_eq!(value["snapshot"]["stale"], true);
    }

    #[tokio::test]
    async fn runtime_inventory_enforces_origin_policy_and_handles_large_snapshots() {
        let mut listeners = Vec::new();
        for index in 0..5_000 {
            listeners.push(InventoryListener {
                server: format!("srv{index}"),
                configured: format!(":{}", 10_000 + (index % 50_000)),
                bound: Some(format!("127.0.0.1:{}", 10_000 + (index % 50_000))),
                network: "tcp".to_string(),
                tls: index % 2 == 0,
                protocols: vec!["h1".to_string(), "h2".to_string()],
                http3: false,
            });
        }
        let admin = admin().with_runtime_introspection_source(Arc::new(FakeInventorySource {
            snapshot: RuntimeInventorySnapshot {
                generation_id: None,
                admin: None,
                listeners,
                certificates: Vec::new(),
                health_checks: Vec::new(),
            },
        }));
        let started = std::time::Instant::now();
        let response = admin.handle(request("GET", "/runtime/inventory", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "large inventory rendering must not block the admin API, took {elapsed:?}"
        );
        let value: Value = serde_json::from_slice(&response.body).expect("inventory JSON");
        assert_eq!(value["listeners"].as_array().unwrap().len(), 5_000);

        // Origin enforcement is the shared admin policy, like every other endpoint.
        let policy = OriginPolicy::from_admin(Some(&caddy_rs_core::AdminConfig {
            enforce_origin: true,
            origins: vec!["https://allowed.example".to_string()],
            ..Default::default()
        }));
        let origin_admin = AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
            .with_origin_policy(policy);
        let response = origin_admin
            .handle(with_origin(
                request("GET", "/runtime/inventory", ""),
                "https://evil.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    // -- PKI endpoints --------------------------------------------------------------------

    fn pki_fixture_data_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    fn pki_admin() -> AdminApi {
        AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
            .with_data_dir(pki_fixture_data_dir())
    }

    #[tokio::test]
    async fn pki_ca_info_reports_the_configured_pki_app_name() {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let config = Config::from_value(json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"name": "Acme Internal Authority", "install_trust": false}
            }}}
        }))
        .expect("pki config");
        store.load(config).expect("activate pki config");
        let admin = AdminApi::new(store).with_data_dir(pki_fixture_data_dir());

        let response = admin.handle(request("GET", "/pki/ca/local", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let info: Value = serde_json::from_slice(&response.body).expect("caInfo JSON");
        assert_eq!(info["id"], "local", "the id stays the config-facing CA id");
        assert_eq!(info["name"], "Acme Internal Authority");

        // An explicit empty name behaves like Caddy's `Name == ""` default.
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let config = Config::from_value(json!({
            "apps": {"pki": {"certificate_authorities": {"local": {"name": ""}}}}
        }))
        .expect("pki config");
        store.load(config).expect("activate pki config");
        let admin = AdminApi::new(store).with_data_dir(pki_fixture_data_dir());
        let info: Value =
            serde_json::from_slice(&admin.handle(request("GET", "/pki/ca/local", "")).await.body)
                .expect("caInfo JSON");
        assert_eq!(info["name"], "Caddy Local Authority");
    }

    #[tokio::test]
    async fn pki_ca_metadata_chain_and_certificate_files() {
        let admin = pki_admin();

        let response = admin.handle(request("GET", "/pki/ca/local", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let info: Value = serde_json::from_slice(&response.body).expect("caInfo JSON");
        assert_eq!(info["id"], "local");
        // Caddy's default CA name when the active config does not name the CA.
        assert_eq!(info["name"], "Caddy Local Authority");
        assert_eq!(info["root_common_name"], "caddy-rs test root");
        assert_eq!(
            info["intermediate_common_name"],
            "caddy-rs test intermediate"
        );
        let root_pem = info["root_certificate"].as_str().expect("root PEM");
        assert!(
            root_pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "{root_pem}"
        );
        assert!(root_pem.ends_with("-----END CERTIFICATE-----\n"));
        let intermediate_pem = info["intermediate_certificate"]
            .as_str()
            .expect("intermediate PEM");
        assert!(intermediate_pem.contains("BEGIN CERTIFICATE"));

        // Caddy's /certificates: intermediate chain first, root last.
        let response = admin
            .handle(request("GET", "/pki/ca/local/certificates", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/pem-certificate-chain")
        );
        let chain = body_string(&response);
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(chain.starts_with(intermediate_pem));
        assert!(chain.ends_with(root_pem));

        // caddy-rs extension: individual PEM files by Caddy file name.
        for (name, expected) in [
            ("root.crt", root_pem),
            ("root.pem", root_pem),
            ("intermediate.crt", intermediate_pem),
            ("intermediate.pem", intermediate_pem),
        ] {
            let response = admin
                .handle(request(
                    "GET",
                    &format!("/pki/ca/local/certificates/{name}"),
                    "",
                ))
                .await;
            assert_eq!(response.status, StatusCode::OK, "{name}");
            assert_eq!(
                response
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/x-pem-file"),
                "{name}"
            );
            assert_eq!(body_string(&response), expected, "{name}");
        }

        let response = admin
            .handle(request("GET", "/pki/ca/local/certificates/root.key", ""))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        // A second CA is listed and readable independently.
        let response = admin.handle(request("GET", "/pki/ca/staging", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let info: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(info["root_common_name"], "caddy-rs staging root");
    }

    #[tokio::test]
    async fn pki_unknown_ca_and_malformed_paths_are_located() {
        let admin = pki_admin();

        let response = admin.handle(request("GET", "/pki/ca/nope", "")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            error["error"],
            "no certificate authority configured with id: nope"
        );

        // The bare `/pki` path redirects to `/pki/` (Caddy's ServeMux canonicalisation).
        let response = admin.handle(request("GET", "/pki", "")).await;
        assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers.get(http::header::LOCATION).unwrap(),
            "/pki/"
        );
        for path in ["/pki/", "/pki/ca/", "/pki/ca/local/nope"] {
            assert_eq!(
                admin.handle(request("GET", path, "")).await.status,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }

        // Path traversal / invalid id is rejected as a located 400.
        let response = admin.handle(request("GET", "/pki/ca/..", "")).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            error["error"].as_str().unwrap().contains("invalid CA id"),
            "{error}"
        );

        // The PKI surface is read-only.
        for (method, path) in [
            ("POST", "/pki/ca/local"),
            ("PUT", "/pki/ca/local/certificates"),
            ("DELETE", "/pki/ca/local"),
        ] {
            let response = admin.handle(request(method, path, "")).await;
            assert_eq!(
                response.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
        }
    }

    #[tokio::test]
    async fn pki_incomplete_and_malformed_cas_report_500_with_location() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ca_dir = directory.path().join("pki/authorities/incomplete");
        std::fs::create_dir_all(&ca_dir).unwrap();
        let admin = AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
            .with_data_dir(directory.path());

        let response = admin.handle(request("GET", "/pki/ca/incomplete", "")).await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let error: Value = serde_json::from_slice(&response.body).unwrap();
        let message = error["error"].as_str().unwrap();
        assert!(
            message.contains("failed to get root and intermediate cert"),
            "{message}"
        );
        assert!(message.contains("root.crt"), "{message}");

        std::fs::write(ca_dir.join("root.crt"), b"garbage").unwrap();
        let response = admin.handle(request("GET", "/pki/ca/incomplete", "")).await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body_string(&response).contains("invalid PEM"));
    }

    #[tokio::test]
    async fn pki_data_dir_falls_back_to_the_active_storage_root_and_override_wins() {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let fixture = pki_fixture_data_dir();
        let config = json!({
            "admin": {"listen": "127.0.0.1:0"},
            "storage": {"module": "file_system", "root": fixture.to_string_lossy()},
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        });
        assert_eq!(
            load(&AdminApi::new(Arc::clone(&store)), &config.to_string())
                .await
                .status,
            StatusCode::OK
        );

        // No explicit data dir: the active generation's `storage.root` is used.
        let admin = AdminApi::new(Arc::clone(&store));
        assert_eq!(
            admin
                .handle(request("GET", "/pki/ca/local", ""))
                .await
                .status,
            StatusCode::OK
        );

        // An explicit data dir wins over the configuration.
        let empty = tempfile::tempdir().unwrap();
        let admin = admin.with_data_dir(empty.path());
        assert_eq!(
            admin
                .handle(request("GET", "/pki/ca/local", ""))
                .await
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn pki_endpoints_are_behind_admin_origin_enforcement() {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let config = json!({
            "admin": {
                "listen": "127.0.0.1:0",
                "enforce_origin": true,
                "origins": ["https://allowed.example"]
            },
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        });
        let admin = AdminApi::new(Arc::clone(&store)).with_data_dir(pki_fixture_data_dir());
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin.handle(request("GET", "/pki/ca/local", "")).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "origin enforcement applies"
        );
        let response = admin
            .handle(with_origin(
                request("GET", "/pki/ca/local", ""),
                "https://allowed.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
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

    // ---- CORS / origin + config path parity (T-ADMIN-030) ---------------------------------

    fn cors_request(method: &str, path: &str) -> AdminRequest {
        request(method, path, "")
    }

    fn with_origin_and_host(mut request: AdminRequest, origin: &str, host: &str) -> AdminRequest {
        request
            .headers
            .insert(http::header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_str(host).unwrap());
        request
    }

    #[tokio::test]
    async fn cors_headers_and_preflight_match_caddy() {
        let admin = admin();
        // Default admin policy: implicit loopback origins for localhost:2019.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("GET", "/config/"),
                "http://localhost:2019",
                "localhost:2019",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:2019"
        );
        assert!(
            response.headers.get(http::header::VARY).is_none(),
            "Caddy v2.11.7 does not send Vary"
        );

        // Path/query is stripped from the echoed origin.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("GET", "/config/"),
                "http://localhost:2019/some/path?q=1",
                "localhost:2019",
            ))
            .await;
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:2019"
        );

        // Preflight OPTIONS: CORS capability headers plus Caddy's method error.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("OPTIONS", "/config/"),
                "http://localhost:2019",
                "localhost:2019",
            ))
            .await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.body,
            Bytes::from_static(b"{\"error\":\"method OPTIONS not allowed\"}\n")
        );
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            "OPTIONS, GET, POST, PUT, PATCH, DELETE"
        );
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap(),
            "Content-Type, Content-Length, Cache-Control"
        );
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:2019"
        );

        // OPTIONS on /load uses Caddy's generic message.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("OPTIONS", "/load"),
                "http://localhost:2019",
                "localhost:2019",
            ))
            .await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.body,
            Bytes::from_static(b"{\"error\":\"method not allowed\"}\n")
        );

        // OPTIONS on /metrics renders metrics (Caddy's handler ignores the method).
        let response = admin
            .handle(with_origin_and_host(
                cors_request("OPTIONS", "/metrics"),
                "http://localhost:2019",
                "localhost:2019",
            ))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            METRICS_CONTENT_TYPE
        );

        // A disallowed origin is still 403 and must not carry CORS headers.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("GET", "/config/"),
                "http://evil.example",
                "localhost:2019",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(response
            .headers
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());

        // No Origin and no enforcement: no CORS headers.
        let response = admin.handle(cors_request("GET", "/config/")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response
            .headers
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[tokio::test]
    async fn host_enforcement_matches_caddy_dns_rebinding_mitigation() {
        let admin = admin();
        let config = json!({
            "admin": {
                "listen": "127.0.0.1:2019",
                "enforce_origin": true,
                "origins": ["http://allowed.example"]
            },
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        let response = admin
            .handle(with_origin_and_host(
                cors_request("GET", "/config/"),
                "http://allowed.example",
                "allowed.example",
            ))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "{}",
            body_string(&response)
        );
        assert_eq!(
            response
                .headers
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://allowed.example"
        );

        // Wrong Host with an otherwise-allowed Origin is Caddy's 403 host error.
        let response = admin
            .handle(with_origin_and_host(
                cors_request("GET", "/config/"),
                "http://allowed.example",
                "evil.example",
            ))
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(
            body_string(&response),
            "{\"error\":\"host not allowed: evil.example\"}\n"
        );

        // enforce_origin without any Origin: forbidden before host/origin matching finishes.
        let mut no_origin = cors_request("GET", "/config/");
        no_origin.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("allowed.example"),
        );
        let response = admin.handle(no_origin).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn config_path_and_id_edges_match_the_caddy_oracle() {
        let admin = admin();
        let config = json!({
            "admin": {"listen": "127.0.0.1:2019"},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [
                    {"@id": "route0", "handle": [{"@id": "h0", "handler": "static_response", "body": "ok"}]},
                    {"@id": "42", "handle": [{"handler": "static_response", "body": "num"}]}
                ]
            }}}}
        });
        assert_eq!(
            load(&admin, &config.to_string()).await.status,
            StatusCode::OK
        );

        // Missing leaf: null 200 with ETag; traversal errors are 400 like Caddy.
        let response = admin
            .handle(request("GET", "/config/apps/missing", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"null\n"));
        let response = admin
            .handle(request("GET", "/config/apps/missing/deeper", ""))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(&response),
            "{\"error\":\"invalid traversal path at: config/apps/missing/deeper\"}\n"
        );

        let response = admin
            .handle(request(
                "GET",
                "/config/apps/http/servers/srv0/routes/9",
                "",
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(body_string(&response).contains("array index out of bounds: 9"));

        let response = admin
            .handle(request(
                "GET",
                "/config/apps/http/servers/srv0/routes/01",
                "",
            ))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            body_string(&response).contains("invalid array index '01': non-canonical array index")
        );

        // Numeric @id and nested @id paths match Caddy's /id redirect semantics.
        let response = admin.handle(request("GET", "/id/42", "")).await;
        assert_eq!(response.status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["@id"], "42");
        let etag = response
            .headers
            .get(http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            etag.starts_with("\"/config/apps/http/servers/srv0/routes/1 "),
            "{etag}"
        );

        let response = admin
            .handle(request("GET", "/id/42/handle/0/body", ""))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"\"num\"\n"));

        let response = admin.handle(request("GET", "/id/nope", "")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(body_string(&response).contains("unknown object ID 'nope'"));

        // Caddy redirects the bare /pki path to /pki/ with 307.
        let response = admin.handle(request("GET", "/pki", "")).await;
        assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers.get(http::header::LOCATION).unwrap(),
            "/pki/"
        );
    }
}

pub use logging_config::{
    access_log_level, apply_access_log_level, LogLevelOverride, ACCESS_LOGGER_NAMES_VAR,
    LOG_LEVEL_NAMES, LOG_LEVEL_VAR,
};
