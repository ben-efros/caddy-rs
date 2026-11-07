//! Offline, deterministic overhead report for the WASM plugin paths (T-PLUG-012).
//!
//! Run with:
//! `cargo test --offline --locked -p caddy-rs-plug --test bench -- --nocapture`
//!
//! The test prints median/p95 timings for module compilation, instantiation, request handling
//! (fresh vs reused instance) and the external-process host path (handshake separated from the
//! per-request frame round-trip). Assertions are deliberately generous smoke bounds, not CI
//! performance gates: the numbers are the deliverable, the bounds only catch pathological
//! regressions (e.g. a leaked timer/thread per request).
#![cfg(feature = "wasm-runtime")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use caddy_rs_plug::{
    AbiLimits, BodyMode, BridgeFrame, BridgeHeaders, BridgeMethod, CapabilityPolicy,
    DenyAllHostCalls, HostEvent, HostHandshakeConfig, HostService, HostServiceConfig,
    ModuleTransportSpec, PluginDescriptor, PluginLimits, RequestHead, ResponseHead, WasmRuntime,
    WasmRuntimeConfig,
};

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

fn response_frames(body: &[u8]) -> Vec<u8> {
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
    let response = response_frames(b"ok");
    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 4096) "{}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64) (i64.const {})))"#,
        wat_string(&response),
        ((4096_i64) << 32) | response.len() as i64
    )
}

fn config() -> WasmRuntimeConfig {
    WasmRuntimeConfig {
        limits: AbiLimits::spec_defaults(),
        fuel_per_request: 1_000_000,
        request_timeout: Duration::from_secs(1),
        ..WasmRuntimeConfig::default()
    }
}

fn descriptor() -> PluginDescriptor {
    PluginDescriptor {
        name: "bench-guest".to_string(),
        abi: caddy_rs_plug::AbiVersion::new(1, 0),
        capabilities: Vec::new(),
        limits: PluginLimits::default_limits(),
    }
}

fn stats(label: &str, mut samples: Vec<Duration>) -> (f64, f64) {
    samples.sort_unstable();
    let micros = |duration: Duration| duration.as_secs_f64() * 1e6;
    let median = micros(samples[samples.len() / 2]);
    let p95 = micros(samples[(samples.len() * 95 / 100).min(samples.len() - 1)]);
    println!(
        "{label:<34} median {median:>10.1} us   p95 {p95:>10.1} us   (n={})",
        samples.len()
    );
    (median, p95)
}

fn time<F: FnMut()>(iterations: usize, mut operation: F) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed());
    }
    samples
}

fn external_helper() -> ModuleTransportSpec {
    ModuleTransportSpec::Stdio {
        program: env!("CARGO_BIN_EXE_plug_echo_module").to_string(),
        args: Vec::new(),
        env: vec![("PLUG_ECHO_MODE".to_string(), "echo".to_string())],
        inherit_env: false,
    }
}

fn external_config() -> HostServiceConfig {
    HostServiceConfig {
        handshake: HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([caddy_rs_plug::Capability::Log]),
            ..HostHandshakeConfig::default()
        },
        stop_grace: Duration::from_secs(2),
        ..HostServiceConfig::default()
    }
}

fn external_request(service: &mut HostService) {
    let request_id = service
        .open_request(request_head(), 1_000)
        .expect("open request");
    service
        .send_request_body(request_id, b"hello".to_vec())
        .expect("body");
    service
        .end_request(request_id, BridgeHeaders::default())
        .expect("end");
    let mut handler = DenyAllHostCalls;
    loop {
        match service.next_event(&mut handler).expect("event") {
            HostEvent::ResponseEnd(_) => break,
            _ => continue,
        }
    }
}

#[test]
fn wasm_plugin_overhead_report() {
    println!("== caddy-rs WASM plugin overhead (T-PLUG-012) ==");
    let guest = echo_guest();

    let compile = time(20, || {
        let _ = WasmRuntime::compile(config(), &guest).expect("compile");
    });
    stats("module compile (WAT->native)", compile);

    let runtime = WasmRuntime::compile(config(), &guest).expect("compile");
    let instantiate = time(200, || {
        let _ = runtime
            .instantiate(
                &descriptor(),
                &CapabilityPolicy::default(),
                1,
                Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
            )
            .expect("instantiate");
    });
    stats("instantiate (fresh store)", instantiate);

    let mut reused = runtime
        .instantiate(
            &descriptor(),
            &CapabilityPolicy::default(),
            1,
            Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
        )
        .expect("instantiate");
    let request_reused = time(500, || {
        let response = reused
            .handle_request(request_head(), b"", BridgeHeaders::default())
            .expect("request");
        assert_eq!(response.body, b"ok");
    });
    let (_, p95_reused) = stats("request (reused instance)", request_reused);

    let request_full = time(100, || {
        let mut plugin = runtime
            .instantiate(
                &descriptor(),
                &CapabilityPolicy::default(),
                1,
                Arc::new(caddy_rs_plug::wasm::DefaultHostCalls),
            )
            .expect("instantiate");
        let response = plugin
            .handle_request(request_head(), b"", BridgeHeaders::default())
            .expect("request");
        assert_eq!(response.body, b"ok");
    });
    stats("request (instantiate + handle)", request_full);

    let handshake = time(3, || {
        let mut service =
            HostService::spawn("echo", external_helper(), 1, external_config()).expect("spawn");
        service.stop().expect("stop");
    });
    stats("external process spawn+handshake", handshake);

    let mut service =
        HostService::spawn("echo", external_helper(), 1, external_config()).expect("spawn");
    let roundtrip = time(100, || external_request(&mut service));
    stats("external frame round-trip", roundtrip);
    let _ = service.stop();

    // Generous smoke bounds: catch only pathological regressions (e.g. a leaked thread/timer per
    // request), not noise between machines. The printed medians/p95 are the benchmark result.
    assert!(
        p95_reused < 250_000.0,
        "in-process request p95 {p95_reused} us"
    );
}
