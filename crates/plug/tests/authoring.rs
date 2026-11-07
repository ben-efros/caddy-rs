//! Tests for the module-author interface (T-PLUG-001):
//!
//! * runs the documented example module (`src/bin/author_module.rs`) through the reference host,
//!   including its two capability-gated host calls;
//! * checks that every capability, host-call code and `AbiErrorCode` documented in
//!   `docs/PLUGIN-DEVELOPMENT.md` exists in the public API with the same stable value.

use std::time::Duration;

use caddy_rs_plug::{
    AbiErrorCode, BodyMode, BridgeHeaders, BridgeMethod, Capability, CapabilityPolicy,
    DenyAllHostCalls, HostCall, HostCallError, HostCallHandler, HostCallResult, HostEvent,
    HostHandshakeConfig, HostService, HostServiceConfig, LogLevel, ModuleTransportSpec,
    RequestHead, HOST_CALL_HTTP_REQUEST, HOST_CALL_LOG, HOST_CALL_NOW, HOST_CALL_RANDOM,
    HOST_CALL_READ_CONFIG,
};

fn config() -> HostServiceConfig {
    HostServiceConfig {
        handshake: HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([Capability::Log, Capability::Clock]),
            ..HostHandshakeConfig::default()
        },
        stop_grace: Duration::from_secs(2),
        ..HostServiceConfig::default()
    }
}

fn transport() -> ModuleTransportSpec {
    ModuleTransportSpec::Stdio {
        program: env!("CARGO_BIN_EXE_author_module").to_string(),
        args: Vec::new(),
        env: Vec::new(),
        inherit_env: false,
    }
}

fn request_head() -> RequestHead {
    RequestHead {
        method: BridgeMethod::Post,
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        path_and_query: "/echo".to_string(),
        headers: BridgeHeaders::new([("Content-Type".to_string(), "text/plain".to_string())])
            .expect("headers"),
        body: BodyMode::Streamed,
    }
}

#[derive(Default)]
struct CountingHostCalls {
    logs: u32,
    clocks: u32,
    denied: u32,
}

impl HostCallHandler for CountingHostCalls {
    fn handle(
        &mut self,
        _request_id: caddy_rs_plug::RequestId,
        call: HostCall,
    ) -> Result<HostCallResult, HostCallError> {
        match call {
            HostCall::Log { .. } => {
                self.logs += 1;
                Ok(HostCallResult::Logged)
            }
            HostCall::Now => {
                self.clocks += 1;
                Ok(HostCallResult::Now {
                    unix_nanos: 1_700_000_000_000_000_000,
                })
            }
            other => {
                self.denied += 1;
                Err(HostCallError::HostFailure {
                    message: format!("example must not call host-call code {}", other.code()),
                })
            }
        }
    }
}

#[test]
fn documented_example_module_runs_through_the_host() {
    let mut service = HostService::spawn("author-example", transport(), 21, config())
        .expect("example module handshake");
    let pid = service.child_id().expect("child pid");
    assert!(service.session().granted.contains(Capability::Log));
    assert!(service.session().granted.contains(Capability::Clock));

    let request_id = service
        .open_request(request_head(), 2_000)
        .expect("open request");
    service
        .send_request_body(request_id, b"hello author".to_vec())
        .expect("body");
    service
        .end_request(request_id, BridgeHeaders::default())
        .expect("end");

    let mut calls = CountingHostCalls::default();
    let mut status = None;
    let mut body = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut finished = false;
    for _ in 0..12 {
        match service.next_event(&mut calls).expect("event") {
            HostEvent::HostCallCompleted { call_code, .. } => {
                assert!(call_code == HOST_CALL_LOG || call_code == HOST_CALL_NOW);
            }
            HostEvent::ResponseHead(head) => {
                status = Some(head.head.status);
                headers = head
                    .head
                    .headers
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect();
            }
            HostEvent::ResponseBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            HostEvent::ResponseEnd(end) => {
                assert_eq!(end.request_id, request_id);
                finished = true;
                break;
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    assert!(finished, "example did not finish the response");
    assert_eq!(status, Some(200));
    assert_eq!(body, b"hello author");
    assert_eq!(calls.logs, 1, "example must call the log host call once");
    assert_eq!(
        calls.clocks, 1,
        "example must call the clock host call once"
    );
    assert_eq!(calls.denied, 0);
    assert_eq!(
        headers
            .iter()
            .find(|(name, _)| name == "X-Host-Time")
            .map(|(_, value)| value.as_str()),
        Some("1700000000000000000")
    );
    assert_eq!(service.stop().expect("stop"), Some(0));
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

/// Capability table documented in `docs/PLUGIN-DEVELOPMENT.md`.
const DOCUMENTED_CAPABILITIES: &[(&str, u32)] = &[
    ("log", 1),
    ("clock", 2),
    ("random", 3),
    ("http_client", 4),
    ("config_read", 5),
];

/// Host-call table documented in `docs/PLUGIN-DEVELOPMENT.md`.
const DOCUMENTED_HOST_CALLS: &[(&str, u32)] = &[
    ("log", HOST_CALL_LOG),
    ("now", HOST_CALL_NOW),
    ("random", HOST_CALL_RANDOM),
    ("http_request", HOST_CALL_HTTP_REQUEST),
    ("read_config", HOST_CALL_READ_CONFIG),
];

/// Error-code table documented in `docs/PLUGIN-DEVELOPMENT.md`.
const DOCUMENTED_ERROR_CODES: &[(&str, u32)] = &[
    ("capability_denied", 1000),
    ("stale_generation", 1001),
    ("limit_exceeded", 1002),
    ("invalid_request", 1003),
    ("host_failure", 1004),
    ("cancelled", 1005),
    ("unsupported", 1006),
    ("plugin_failed", 1007),
];

#[test]
fn documented_capabilities_match_the_public_enum() {
    assert_eq!(Capability::ALL.len(), DOCUMENTED_CAPABILITIES.len());
    for (name, code) in DOCUMENTED_CAPABILITIES {
        let capability = Capability::from_code(*code)
            .unwrap_or_else(|| panic!("documented capability {name} code {code} missing"));
        assert_eq!(capability.code(), *code, "documented {name}");
        assert_eq!(capability.name(), *name, "documented name {name}");
    }
}

#[test]
fn documented_host_calls_match_the_public_constants_and_variants() {
    assert_eq!(HOST_CALL_LOG, 1);
    assert_eq!(HOST_CALL_NOW, 2);
    assert_eq!(HOST_CALL_RANDOM, 3);
    assert_eq!(HOST_CALL_HTTP_REQUEST, 4);
    assert_eq!(HOST_CALL_READ_CONFIG, 5);
    let calls = [
        (
            "log",
            HostCall::Log {
                level: LogLevel::Info,
                message: String::new(),
                fields: Vec::new(),
            },
            Capability::Log,
        ),
        ("now", HostCall::Now, Capability::Clock),
        ("random", HostCall::Random { len: 1 }, Capability::Random),
        (
            "http_request",
            HostCall::HttpRequest {
                method: BridgeMethod::Get,
                url: "https://example.com/".to_string(),
                headers: BridgeHeaders::default(),
                body: Vec::new(),
            },
            Capability::HttpClient,
        ),
        (
            "read_config",
            HostCall::ReadConfig {
                key: "key".to_string(),
            },
            Capability::ConfigRead,
        ),
    ];
    assert_eq!(calls.len(), DOCUMENTED_HOST_CALLS.len());
    for ((name, call, capability), (documented_name, documented_code)) in
        calls.iter().zip(DOCUMENTED_HOST_CALLS)
    {
        assert_eq!(name, documented_name);
        assert_eq!(call.code(), *documented_code, "host call {name}");
        assert_eq!(call.required_capability(), *capability);
    }
}

#[test]
fn documented_error_codes_match_the_public_enum() {
    for (name, code) in DOCUMENTED_ERROR_CODES {
        let error = AbiErrorCode::from_code(*code)
            .unwrap_or_else(|| panic!("documented error code {name} ({code}) missing"));
        assert_eq!(error.code(), *code, "documented error code {name}");
    }
    assert_eq!(
        AbiErrorCode::from_code(9999),
        None,
        "undefined codes must stay rejected"
    );
    // The deny-all default handler is documented as a safe host default; it exists and is usable.
    let mut deny = DenyAllHostCalls;
    assert!(deny
        .handle(caddy_rs_plug::RequestId::new(1).expect("id"), HostCall::Now)
        .is_err());
}
