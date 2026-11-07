//! In-process WASM host runtime tests (T-PLUG-011).
//!
//! The guests are tiny WAT modules embedded here: a response-returning guest that also makes one
//! host call, a fuel-burning infinite loop, and a host-call-denial probe. All tests run in-process
//! with no network and no floating toolchain: `wasmtime` compiles the WAT directly.

#![cfg(feature = "wasm-runtime")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_plug::{
    AbiErrorCode, AbiLimits, AbiVersion, BodyMode, BridgeFrame, BridgeHeaders, BridgeMethod,
    Capability, CapabilityPolicy, HostCall, HostCallError, HostCallProvider, LogLevel,
    PluginDescriptor, PluginLimits, RequestHead, ResponseHead, WasmError, WasmRuntime,
    WasmRuntimeConfig, Writer,
};

/// A provider that records calls and returns deterministic results.
#[derive(Default)]
struct RecordingHostCalls {
    now_calls: AtomicU32,
    log_calls: AtomicU32,
    random_calls: AtomicU32,
}

impl HostCallProvider for RecordingHostCalls {
    fn log(
        &self,
        _level: LogLevel,
        _message: &str,
        _fields: &[(String, String)],
    ) -> Result<(), HostCallError> {
        self.log_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn now(&self) -> Result<u64, HostCallError> {
        self.now_calls.fetch_add(1, Ordering::SeqCst);
        Ok(1_700_000_000_000_000_000)
    }

    fn random(&self, len: u32) -> Result<Vec<u8>, HostCallError> {
        self.random_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0xAB; len as usize])
    }

    fn http_request(
        &self,
        _method: BridgeMethod,
        _url: &str,
        _headers: &BridgeHeaders,
        _body: &[u8],
    ) -> Result<(u16, BridgeHeaders, Vec<u8>), HostCallError> {
        Err(HostCallError::HostFailure {
            message: "no http client in this test".to_string(),
        })
    }

    fn read_config(&self, _key: &str) -> Result<Option<String>, HostCallError> {
        Ok(None)
    }
}

fn response_frames(body: &[u8]) -> Vec<u8> {
    let limits = AbiLimits::spec_defaults();
    let frames = [
        BridgeFrame::ResponseHead(ResponseHead {
            status: 200,
            headers: BridgeHeaders::new([("X-Guest".to_string(), "wat".to_string())])
                .expect("headers"),
            body: BodyMode::Buffered {
                length: body.len() as u64,
            },
        }),
        BridgeFrame::ResponseBodyChunk(body.to_vec()),
        BridgeFrame::ResponseEnd(BridgeHeaders::default()),
    ];
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend_from_slice(&frame.encode(&limits).expect("encode response frame"));
    }
    bytes
}

fn wat_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

/// Guest: optionally calls `caddy.host_call` once with `call_payload`, then returns `response`.
fn guest_wat(call_payload: Option<&[u8]>, response: &[u8]) -> String {
    let (call_data, call_len) = match call_payload {
        Some(payload) => (wat_string(payload), payload.len()),
        None => (String::new(), 0),
    };
    let call = if call_payload.is_some() {
        format!(
            r#"(local.set $r (call $host_call (i32.const 0) (i32.const {call_len}) (i32.const 2048) (i32.const 64)))
    (if (i64.lt_s (local.get $r) (i64.const 0)) (then (return (local.get $r))))"#
        )
    } else {
        String::new()
    };
    format!(
        r#"(module
  (import "caddy" "host_call" (func $host_call (param i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{call_data}")
  (data (i32.const 4096) "{response_data}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (local $r i64)
    {call}
    (i64.const {response_packed}))
)"#,
        response_data = wat_string(response),
        response_packed = ((4096_i64) << 32) | response.len() as i64,
    )
}

fn fuel_guest() -> &'static str {
    r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0))
)"#
}

fn descriptor(capabilities: Vec<u32>) -> PluginDescriptor {
    PluginDescriptor {
        name: "wasm-guest".to_string(),
        abi: AbiVersion::new(1, 0),
        capabilities,
        limits: PluginLimits::default_limits(),
    }
}

fn request_head() -> RequestHead {
    RequestHead {
        method: BridgeMethod::Post,
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        path_and_query: "/wasm".to_string(),
        headers: BridgeHeaders::default(),
        body: BodyMode::Streamed,
    }
}

fn engine_config() -> WasmRuntimeConfig {
    WasmRuntimeConfig {
        limits: AbiLimits::spec_defaults(),
        fuel_per_request: 10_000_000,
        request_timeout: Duration::ZERO,
        ..WasmRuntimeConfig::default()
    }
}

fn host_call_now_payload() -> Vec<u8> {
    let limits = AbiLimits::spec_defaults();
    let mut writer = Writer::new();
    HostCall::Now
        .encode(&mut writer, &limits)
        .expect("encode HostCall::Now");
    writer.into_vec()
}

#[test]
fn guest_echoes_a_request_and_makes_a_host_call() {
    let response = response_frames(b"hello from wasm");
    let call = host_call_now_payload();
    let wat = guest_wat(Some(&call), &response);
    let runtime = WasmRuntime::compile(engine_config(), wat).expect("compile WAT guest");
    let policy = CapabilityPolicy::with_capabilities([Capability::Clock]);
    let provider = Arc::new(RecordingHostCalls::default());
    let mut plugin = runtime
        .instantiate(
            &descriptor(vec![Capability::Clock.code()]),
            &policy,
            1,
            provider.clone(),
        )
        .expect("instantiate");
    assert!(plugin.negotiated().granted.contains(Capability::Clock));
    let response = plugin
        .handle_request(
            request_head(),
            b"request body is ignored by this WAT guest",
            BridgeHeaders::default(),
        )
        .expect("handle request");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello from wasm");
    assert_eq!(
        response
            .headers
            .iter()
            .find(|(name, _)| *name == "X-Guest")
            .map(|(_, value)| value),
        Some("wat")
    );
    assert_eq!(provider.now_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fuel_exhaustion_is_a_typed_limit_error_and_host_stays_healthy() {
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            fuel_per_request: 10_000,
            ..engine_config()
        },
        fuel_guest(),
    )
    .expect("compile fuel guest");
    let policy = CapabilityPolicy::default();
    let mut plugin = runtime
        .instantiate(
            &descriptor(Vec::new()),
            &policy,
            2,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect("instantiate");
    let error = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("fuel must run out");
    assert!(matches!(error, WasmError::FuelExhausted), "got {error:?}");
    assert_eq!(error.abi_code(), AbiErrorCode::LimitExceeded);

    // The host is still healthy: another runtime/plugin works normally.
    let response = response_frames(b"still healthy");
    let healthy =
        WasmRuntime::compile(engine_config(), guest_wat(None, &response)).expect("compile");
    let mut plugin = healthy
        .instantiate(
            &descriptor(Vec::new()),
            &policy,
            2,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect("instantiate healthy");
    let response = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect("healthy request");
    assert_eq!(response.body, b"still healthy");
}

#[test]
fn wall_clock_timeout_is_a_typed_cancellation() {
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            // Too much fuel to run out within the deadline; the epoch timer must fire first.
            fuel_per_request: 1_000_000_000_000,
            request_timeout: Duration::from_millis(50),
            ..engine_config()
        },
        fuel_guest(),
    )
    .expect("compile timeout guest");
    let mut plugin = runtime
        .instantiate(
            &descriptor(Vec::new()),
            &CapabilityPolicy::default(),
            3,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect("instantiate");
    let error = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("guest must time out");
    assert!(matches!(error, WasmError::Timeout), "got {error:?}");
    assert_eq!(error.abi_code(), AbiErrorCode::Cancelled);
}

#[test]
fn denied_host_call_returns_the_typed_capability_error_to_the_guest() {
    let call = host_call_now_payload();
    let response = response_frames(b"should not be reached");
    let wat = guest_wat(Some(&call), &response);
    let runtime = WasmRuntime::compile(engine_config(), wat).expect("compile");
    // The descriptor asks only for log; the guest attempts `now`, which requires clock.
    let policy = CapabilityPolicy::with_capabilities([Capability::Log]);
    let mut plugin = runtime
        .instantiate(
            &descriptor(vec![Capability::Log.code()]),
            &policy,
            4,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect("instantiate");
    let error = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("clock host call must be denied");
    assert!(
        matches!(
            error,
            WasmError::GuestAbi {
                code: AbiErrorCode::CapabilityDenied
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn declaring_a_capability_the_policy_does_not_grant_is_rejected_before_instantiation() {
    let response = response_frames(b"unreachable");
    let runtime =
        WasmRuntime::compile(engine_config(), guest_wat(None, &response)).expect("compile");
    let policy = CapabilityPolicy::with_capabilities([Capability::Log]);
    let error = runtime
        .instantiate(
            &descriptor(vec![Capability::Random.code()]),
            &policy,
            5,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect_err("ungranted capability declaration must be rejected");
    assert!(
        matches!(
            error,
            WasmError::Negotiation {
                code: AbiErrorCode::CapabilityDenied,
                ..
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn oversized_request_body_is_rejected_before_guest_execution() {
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            max_request_body_bytes: 4,
            ..engine_config()
        },
        guest_wat(None, &response_frames(b"unreachable")),
    )
    .expect("compile");
    let mut plugin = runtime
        .instantiate(
            &descriptor(Vec::new()),
            &CapabilityPolicy::default(),
            6,
            Arc::new(RecordingHostCalls::default()),
        )
        .expect("instantiate");
    let error = plugin
        .handle_request(request_head(), b"too large", BridgeHeaders::default())
        .expect_err("oversized request");
    assert!(matches!(error, WasmError::LimitExceeded { .. }));
    assert_eq!(error.abi_code(), AbiErrorCode::InvalidRequest);
}
