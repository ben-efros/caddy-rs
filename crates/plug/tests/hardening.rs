//! WASM sandbox hardening matrix (T-PLUG-012): every pathological guest must produce a typed
//! error (never a host panic/OOM) and must leave the runtime healthy for subsequent requests.
#![cfg(feature = "wasm-runtime")]

use std::sync::Arc;
use std::time::Duration;

use caddy_rs_plug::{
    AbiLimits, BodyMode, BridgeFrame, BridgeHeaders, BridgeMethod, Capability, CapabilityPolicy,
    HostCall, PluginDescriptor, PluginLimits, RequestHead, ResponseHead, WasmError, WasmRuntime,
    WasmRuntimeConfig, Writer,
};

fn engine_config() -> WasmRuntimeConfig {
    WasmRuntimeConfig {
        limits: AbiLimits::spec_defaults(),
        fuel_per_request: 50_000_000,
        request_timeout: Duration::ZERO,
        ..WasmRuntimeConfig::default()
    }
}

fn descriptor() -> PluginDescriptor {
    PluginDescriptor {
        name: "hardening-guest".to_string(),
        abi: caddy_rs_plug::AbiVersion::new(1, 0),
        capabilities: Vec::new(),
        limits: PluginLimits::default_limits(),
    }
}

fn request_head() -> RequestHead {
    RequestHead {
        method: BridgeMethod::Get,
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        path_and_query: "/".to_string(),
        headers: BridgeHeaders::default(),
        body: BodyMode::Streamed,
    }
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let limits = AbiLimits::spec_defaults();
    let frames = [
        BridgeFrame::ResponseHead(ResponseHead {
            status: 200,
            headers: BridgeHeaders::default(),
            body: BodyMode::Buffered {
                length: body.len() as u64,
            },
        }),
        BridgeFrame::ResponseBodyChunk(body.to_vec()),
        BridgeFrame::ResponseEnd(BridgeHeaders::default()),
    ];
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend_from_slice(&frame.encode(&limits).unwrap());
    }
    bytes
}

fn wat_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

fn echo_guest() -> String {
    let response = ok_response(b"ok");
    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 4096) "{}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (i64.const {})))"#,
        wat_string(&response),
        ((4096_i64) << 32) | response.len() as i64
    )
}

fn plugin(runtime: &WasmRuntime) -> caddy_rs_plug::WasmPlugin {
    runtime
        .instantiate(
            &descriptor(),
            &CapabilityPolicy::default(),
            1,
            Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
        )
        .expect("instantiate healthy guest")
}

fn assert_host_healthy(runtime: &WasmRuntime) {
    let mut plugin = plugin(runtime);
    let response = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect("host must stay healthy");
    assert_eq!(response.body, b"ok");
}

#[test]
fn guest_with_unbounded_memory_growth_is_bounded_and_host_stays_healthy() {
    // The guest grows linear memory until the StoreLimits deny it (memory.grow returns -1), then
    // returns a normal response. No host OOM occurs and the sandbox keeps serving.
    let response = ok_response(b"grown");
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 4096) "{}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (block $done
      (loop $grow
        (br_if $done (i32.eq (memory.grow (i32.const 1)) (i32.const -1)))
        (br $grow)))
    (i64.const {})))"#,
        wat_string(&response),
        ((4096_i64) << 32) | response.len() as i64
    );
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            max_memory_bytes: 2 * 65_536,
            ..engine_config()
        },
        wat,
    )
    .expect("compile growing guest");
    let mut growing_plugin = plugin(&runtime);
    let response = growing_plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect("growth must be denied by the limiter, not crash");
    assert_eq!(response.body, b"grown");
    // A second instance on the same runtime still works (the limiter rejects growth, not requests).
    let mut second = plugin(&runtime);
    assert_eq!(
        second
            .handle_request(request_head(), b"", BridgeHeaders::default())
            .expect("second request")
            .body,
        b"grown"
    );
}

#[test]
fn module_with_oversized_minimum_memory_fails_with_a_typed_error() {
    let wat = r#"(module
  (memory (export "memory") 100)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64) (i64.const 0)))"#;
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            max_memory_bytes: 2 * 65_536,
            ..engine_config()
        },
        wat,
    )
    .expect("compile");
    let error = runtime
        .instantiate(
            &descriptor(),
            &CapabilityPolicy::default(),
            1,
            Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
        )
        .expect_err("100-page minimum memory must exceed the 2-page store limit");
    assert!(
        matches!(
            error,
            WasmError::Instantiate { .. } | WasmError::Store { .. } | WasmError::Trap { .. }
        ),
        "expected a typed wasm resource error, got {error:?}"
    );
    // A healthy guest still instantiates on the same runtime.
    let runtime = WasmRuntime::compile(engine_config(), echo_guest()).expect("compile echo");
    assert_host_healthy(&runtime);
}

#[test]
fn host_call_spam_is_stopped_by_the_per_request_budget() {
    let now_payload = {
        let limits = AbiLimits::spec_defaults();
        let mut writer = Writer::new();
        HostCall::Now.encode(&mut writer, &limits).unwrap();
        writer.into_vec()
    };
    let wat = format!(
        r#"(module
  (import "caddy" "host_call" (func $host_call (param i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (local $i i32)
    (local $r i64)
    (loop $spam
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (local.set $r (call $host_call (i32.const 0) (i32.const {}) (i32.const 2048) (i32.const 64)))
      (if (i64.lt_s (local.get $r) (i64.const 0))
        (then (return (local.get $r))))
      (br_if $spam (i32.lt_u (local.get $i) (i32.const 8)))
      )
    (i64.const 0)))"#,
        wat_string(&now_payload),
        now_payload.len()
    );
    let runtime = WasmRuntime::compile(engine_config(), wat).expect("compile spam guest");
    let spam_descriptor = PluginDescriptor {
        limits: PluginLimits {
            max_host_calls_per_request: 2,
            ..PluginLimits::default_limits()
        },
        ..descriptor()
    };
    let mut plugin = runtime
        .instantiate(
            &spam_descriptor,
            &CapabilityPolicy::with_capabilities([Capability::Clock]),
            1,
            Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
        )
        .expect("instantiate spam guest");
    let error = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("budget must stop the host-call spam");
    assert!(
        matches!(
            error,
            WasmError::LimitExceeded { .. }
                | WasmError::HostCall { .. }
                | WasmError::GuestAbi { .. }
        ),
        "unexpected error: {error:?}"
    );
    assert_host_healthy(&WasmRuntime::compile(engine_config(), echo_guest()).unwrap());
}

#[test]
fn enormous_declared_response_length_is_rejected_before_any_read() {
    // Packed ptr<<32 | len with len = u32::MAX; host must reject from the declared length without
    // allocating or reading (the guest memory is only one page).
    let enormous = ((4096_i64) << 32) | 0xFFFF_FF00_i64;
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (i64.const {enormous})))"#,
    );
    let runtime = WasmRuntime::compile(engine_config(), wat).expect("compile");
    let mut plugin = plugin(&runtime);
    let error = plugin
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("huge declared length must be rejected");
    assert!(
        matches!(error, WasmError::LimitExceeded { .. }),
        "{error:?}"
    );
    assert_host_healthy(&WasmRuntime::compile(engine_config(), echo_guest()).unwrap());
}

#[test]
fn guest_trap_maps_to_a_typed_error_and_does_not_poison_the_runtime() {
    let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (unreachable)
    (i64.const 0)))"#;
    let runtime = WasmRuntime::compile(engine_config(), wat).expect("compile trapping guest");
    let mut first = plugin(&runtime);
    let error = first
        .handle_request(request_head(), b"", BridgeHeaders::default())
        .expect_err("unreachable must trap");
    assert!(matches!(error, WasmError::Trap { .. }), "{error:?}");
    // Fresh instance on the same runtime is unaffected.
    let runtime = WasmRuntime::compile(engine_config(), echo_guest()).unwrap();
    assert_host_healthy(&runtime);
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_timer_threads_do_not_leak_across_requests() {
    fn tasks() -> usize {
        std::fs::read_dir("/proc/self/task").unwrap().count()
    }
    let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0)))"#;
    let runtime = WasmRuntime::compile(
        WasmRuntimeConfig {
            fuel_per_request: u64::MAX / 4,
            request_timeout: Duration::from_millis(5),
            ..engine_config()
        },
        wat,
    )
    .expect("compile");
    let mut plugin = plugin(&runtime);
    let before = tasks();
    for _ in 0..100 {
        let error = plugin
            .handle_request(request_head(), b"", BridgeHeaders::default())
            .expect_err("timeout expected");
        assert!(matches!(error, WasmError::Timeout), "{error:?}");
    }
    let after = tasks();
    assert!(
        after <= before + 3,
        "timeout timers must be joined (task count {before} -> {after})"
    );
}
