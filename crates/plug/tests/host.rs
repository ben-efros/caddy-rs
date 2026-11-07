//! Host lifecycle tests for external module services (T-PLUG-021): real child processes speaking
//! the protocol over stdio, generation scoping, crash isolation, capability denial and reaping.
//!
//! No network and no external services: the module is the tiny `plug_echo_module` binary built from
//! this crate (`CARGO_BIN_EXE_plug_echo_module`), and process liveness is asserted through `/proc`
//! on Linux (the CI platform).

use std::io::Write;
use std::time::{Duration, Instant};

use caddy_rs_core::GenerationResource;
use caddy_rs_plug::{
    AbiErrorCode, BodyMode, BridgeHeaders, BridgeMethod, Capability, CapabilityPolicy,
    DenyAllHostCalls, GenerationModule, GenerationScope, HostCallError, HostError, HostEvent,
    HostHandshakeConfig, HostService, HostServiceConfig, ModuleSupervisor, ModuleTransportSpec,
    PluginLimits, RequestHead, RestartPolicy,
};

fn helper(mode: &str) -> ModuleTransportSpec {
    ModuleTransportSpec::Stdio {
        program: env!("CARGO_BIN_EXE_plug_echo_module").to_string(),
        args: Vec::new(),
        env: vec![("PLUG_ECHO_MODE".to_string(), mode.to_string())],
        inherit_env: false,
    }
}

fn grant_log() -> CapabilityPolicy {
    CapabilityPolicy::with_capabilities([Capability::Log])
}

fn config(policy: CapabilityPolicy) -> HostServiceConfig {
    HostServiceConfig {
        handshake: HostHandshakeConfig {
            policy,
            ..HostHandshakeConfig::default()
        },
        stop_grace: Duration::from_secs(2),
        ..HostServiceConfig::default()
    }
}

fn request_head() -> RequestHead {
    RequestHead {
        method: BridgeMethod::Post,
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        path_and_query: "/echo".to_string(),
        headers: BridgeHeaders::default(),
        body: BodyMode::Streamed,
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[cfg(target_os = "linux")]
fn process_reaped(pid: u32) -> bool {
    !std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[test]
fn handshake_succeeds_and_a_request_round_trips_through_the_host() {
    let mut service = HostService::spawn("echo", helper("echo"), 7, config(grant_log()))
        .expect("spawn+handshake");
    assert!(service.is_running());
    assert!(service.session().granted.contains(Capability::Log));
    assert_eq!(service.generation(), 7);
    let pid = service.child_id().expect("child pid");
    let request_id = service
        .open_request(request_head(), 1_000)
        .expect("open request");
    service
        .send_request_body(request_id, b"hello ".to_vec())
        .expect("body 1");
    service
        .send_request_body(request_id, b"world".to_vec())
        .expect("body 2");
    service
        .end_request(request_id, BridgeHeaders::default())
        .expect("end request");

    let mut handler = DenyAllHostCalls;
    let mut status = None;
    let mut body = Vec::new();
    let mut finished = false;
    for _ in 0..8 {
        match service.next_event(&mut handler).expect("event") {
            HostEvent::ResponseHead(head) => status = Some(head.head.status),
            HostEvent::ResponseBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            HostEvent::ResponseEnd(end) => {
                assert_eq!(end.request_id, request_id);
                finished = true;
                break;
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(finished, "response end not seen");
    assert_eq!(status, Some(200));
    assert_eq!(body, b"hello world");
    assert_eq!(service.stop().expect("stop"), Some(0));
    #[cfg(target_os = "linux")]
    assert!(process_reaped(pid), "child {pid} must be reaped");
}

#[test]
fn handshake_rejects_ungranted_capabilities_and_reaps_the_child() {
    let error = HostService::spawn(
        "echo",
        helper("echo"),
        1,
        config(CapabilityPolicy::deny_all()),
    )
    .expect_err("handshake must be rejected");
    match error {
        HostError::Handshake(caddy_rs_plug::HandshakeError::Capability(
            caddy_rs_plug::CapabilityError::NotGranted { capability },
        )) => assert_eq!(capability, Capability::Log),
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(error.abi_code(), AbiErrorCode::CapabilityDenied);
}

#[test]
fn capability_denial_is_surfaced_to_the_module() {
    let mut service = HostService::spawn("echo", helper("hostcall-clock"), 2, config(grant_log()))
        .expect("spawn");
    let pid = service.child_id().expect("pid");
    let request_id = service
        .open_request(request_head(), 500)
        .expect("open request");
    service
        .end_request(request_id, BridgeHeaders::default())
        .expect("end");

    let mut handler = DenyAllHostCalls;
    let mut denied = None;
    for _ in 0..4 {
        match service.next_event(&mut handler) {
            Ok(HostEvent::HostCallDenied { error, .. }) => {
                denied = Some(error);
                break;
            }
            Ok(_) => continue,
            Err(error) => panic!("unexpected transport error before denial: {error:?}"),
        }
    }
    let error = denied.expect("clock host call must be denied");
    assert!(matches!(
        error,
        HostCallError::CapabilityDenied {
            capability: Capability::Clock,
            ..
        }
    ));
    // The helper exits(13) after observing the request-scoped CapabilityDenied error frame.
    assert_eq!(service.stop().expect("stop"), Some(13));
    #[cfg(target_os = "linux")]
    assert!(process_reaped(pid));
}

#[test]
fn generation_stop_reaps_the_child_within_the_grace_period() {
    let scope = GenerationScope::new(9);
    let module = scope
        .spawn("echo", helper("echo"), config(grant_log()))
        .expect("scope spawn");
    let pid = module.with_service(|service| service.child_id().expect("pid"));
    assert_eq!(scope.names(), vec!["echo".to_string()]);
    let started = Instant::now();
    block_on(async { module.start().await }).expect("generation start");
    let codes = scope.stop().expect("scope stop");
    assert_eq!(codes, vec![Some(0)]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "clean shutdown must not consume the whole grace period"
    );
    block_on(async { module.cleanup().await }).expect("cleanup idempotent");
    assert!(scope.names().is_empty());
    #[cfg(target_os = "linux")]
    assert!(process_reaped(pid));
}

#[test]
fn crash_mid_request_fails_the_session_but_not_other_services() {
    let mut crashing = HostService::spawn("crash", helper("crash"), 3, config(grant_log()))
        .expect("spawn crash module");
    let crashing_pid = crashing.child_id().expect("pid");
    let request_id = crashing
        .open_request(request_head(), 500)
        .expect("open request");
    let mut handler = DenyAllHostCalls;
    let error = crashing
        .next_event(&mut handler)
        .expect_err("crash must fail the session");
    assert_eq!(error.abi_code(), AbiErrorCode::PluginFailed);
    let failed = crashing.take_failed_requests();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, request_id);
    assert_eq!(crashing.stop().expect("stop crash module"), Some(7));
    #[cfg(target_os = "linux")]
    assert!(process_reaped(crashing_pid));

    // The host process (this test) is unaffected: a second service still completes a request.
    let mut healthy = HostService::spawn("echo", helper("echo"), 3, config(grant_log()))
        .expect("spawn healthy module");
    let healthy_pid = healthy.child_id().expect("pid");
    let id = healthy
        .open_request(request_head(), 500)
        .expect("open request");
    healthy
        .send_request_body(id, b"still alive".to_vec())
        .expect("body");
    healthy
        .end_request(id, BridgeHeaders::default())
        .expect("end");
    let mut done = false;
    for _ in 0..6 {
        if matches!(
            healthy.next_event(&mut handler).expect("healthy event"),
            HostEvent::ResponseEnd(_)
        ) {
            done = true;
            break;
        }
    }
    assert!(done);
    assert_eq!(healthy.stop().expect("stop healthy"), Some(0));
    #[cfg(target_os = "linux")]
    assert!(process_reaped(healthy_pid));
}

#[test]
fn oversized_frames_are_rejected_and_the_child_reaped() {
    let mut service = HostService::spawn("oversized", helper("oversized"), 4, config(grant_log()))
        .expect("spawn");
    let pid = service.child_id().expect("pid");
    let mut handler = DenyAllHostCalls;
    let error = service
        .next_event(&mut handler)
        .expect_err("oversized frame must fail");
    assert_eq!(error.abi_code(), AbiErrorCode::InvalidRequest);
    assert!(matches!(error, HostError::Protocol(_)), "got {error:?}");
    assert_eq!(service.stop().expect("stop"), Some(8));
    #[cfg(target_os = "linux")]
    assert!(process_reaped(pid));
}

#[test]
fn default_supervision_never_restarts_crashes() {
    let mut supervisor =
        ModuleSupervisor::start("crash", helper("crash"), 5, config(grant_log())).expect("start");
    {
        let service = supervisor.service_mut().expect("service");
        let _ = service.open_request(request_head(), 100).expect("open");
        let mut handler = DenyAllHostCalls;
        let _ = service.next_event(&mut handler).expect_err("crash");
        let _ = service.poll_child();
    }
    let error = supervisor
        .handle_crash()
        .expect_err("no restart by default");
    assert!(matches!(error, HostError::CrashIsolated { code: Some(7) }));
    assert_eq!(supervisor.restarts_used(), 0);
    assert!(supervisor.service_mut().is_none());
    let _ = supervisor.stop();
}

#[test]
fn configured_restart_policy_restarts_with_backoff_and_reports_exhaustion() {
    let mut config = config(grant_log());
    config.restart = RestartPolicy::OnFailure {
        max_restarts: 1,
        backoff: Duration::from_millis(1),
    };
    let mut supervisor =
        ModuleSupervisor::start("crash", helper("crash"), 6, config).expect("start");
    {
        let service = supervisor.service_mut().expect("service");
        let _ = service.open_request(request_head(), 100).expect("open");
        let mut handler = DenyAllHostCalls;
        let _ = service.next_event(&mut handler).expect_err("crash");
    }
    supervisor.handle_crash().expect("restart within budget");
    assert_eq!(supervisor.restarts_used(), 1);
    {
        let service = supervisor.service_mut().expect("restarted service");
        let _ = service.open_request(request_head(), 100).expect("open");
        let mut handler = DenyAllHostCalls;
        let _ = service.next_event(&mut handler).expect_err("second crash");
    }
    let error = supervisor.handle_crash().expect_err("budget exhausted");
    assert!(matches!(error, HostError::RestartExhausted { attempts: 1 }));
    let _ = supervisor.stop();
}

#[test]
fn transport_reads_are_bounded_and_malformed_input_is_typed() {
    // A frame header declaring an impossible payload is rejected before any allocation.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x29, 0xFF, 0xFF, 0xFF, 0x7F]);
    let mut reader = std::io::Cursor::new(bytes);
    let limits = caddy_rs_plug::AbiLimits::spec_defaults();
    let error = caddy_rs_plug::read_frame(&mut reader, &limits).expect_err("oversized");
    assert_eq!(error.abi_code(), AbiErrorCode::InvalidRequest);

    // A write to a broken transport is an I/O error, not a panic.
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let frame = caddy_rs_plug::ProtocolFrame::Error(caddy_rs_plug::ErrorFrame {
        request_id: None,
        fatal: true,
        code: AbiErrorCode::Cancelled,
        message: String::new(),
    });
    let error = caddy_rs_plug::write_frame(&mut Broken, &frame, &limits).expect_err("write");
    assert!(matches!(error, HostError::Io { .. }));
}

#[test]
fn generation_module_is_a_core_generation_resource() {
    fn assert_generation_resource<T: GenerationResource>() {}
    assert_generation_resource::<GenerationModule>();

    let service =
        HostService::spawn("echo", helper("echo"), 11, config(grant_log())).expect("spawn");
    let pid = service.child_id().expect("pid");
    let module = GenerationModule::new(service);
    assert_eq!(module.generation(), 11);
    block_on(async { module.start().await }).expect("start");
    block_on(async { <GenerationModule as GenerationResource>::stop(&module).await })
        .expect("stop");
    block_on(async { module.cleanup().await }).expect("cleanup");
    #[cfg(target_os = "linux")]
    assert!(process_reaped(pid));
}

#[test]
fn host_limits_are_reported_in_the_session() {
    let mut config = config(grant_log());
    config.handshake.host_limits = PluginLimits {
        max_request_body_bytes: 4096,
        max_response_body_bytes: 8192,
        max_host_calls_per_request: 3,
        max_memory_bytes: 1024 * 1024,
    };
    config.handshake.max_in_flight_requests = 2;
    config.handshake.body_window_bytes = 1024;
    let mut service = HostService::spawn("echo", helper("echo"), 12, config).expect("spawn");
    let session = service.session();
    assert_eq!(session.limits.max_request_body_bytes, 4096);
    assert_eq!(session.limits.max_host_calls_per_request, 3);
    assert_eq!(session.max_in_flight_requests, 2);
    assert_eq!(session.body_window_bytes, 1024);
    assert_eq!(service.stop().expect("stop"), Some(0));
}
