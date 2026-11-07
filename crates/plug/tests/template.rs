//! T-PLUG-002: the out-of-tree module template must compile independently and work through the
//! reference host.
//!
//! The template lives at `crates/plug/template/` with its own `[workspace]` and path dependency on
//! this crate, so it is intentionally **not** a member of the caddy-rs workspace. This test builds
//! it with `cargo build --locked` (independent target directory) and then runs the built
//! binary through `HostService` for one request round-trip.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use caddy_rs_plug::{
    BodyMode, BridgeHeaders, BridgeMethod, Capability, CapabilityPolicy, HostCallError,
    HostCallHandler, HostCallResult, HostEvent, HostHandshakeConfig, HostService,
    HostServiceConfig, ModuleTransportSpec, RequestHead, RequestId,
};

fn config() -> HostServiceConfig {
    HostServiceConfig {
        handshake: HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([Capability::Log]),
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
        path_and_query: "/template".to_string(),
        headers: BridgeHeaders::default(),
        body: BodyMode::Streamed,
    }
}

struct HostCalls {
    logs: u32,
}

impl HostCallHandler for HostCalls {
    fn handle(
        &mut self,
        _request_id: RequestId,
        call: caddy_rs_plug::HostCall,
    ) -> Result<HostCallResult, HostCallError> {
        match call {
            caddy_rs_plug::HostCall::Log { .. } => {
                self.logs += 1;
                Ok(HostCallResult::Logged)
            }
            other => Err(HostCallError::HostFailure {
                message: format!("template test only implements log, got {}", other.code()),
            }),
        }
    }
}

#[test]
fn template_compiles_and_serves_a_request() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("template/Cargo.toml");
    assert!(
        manifest.is_file(),
        "template manifest missing: {}",
        manifest.display()
    );
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // Keep template build artifacts out of the source tree and the main workspace target dir.
    let target_dir = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("caddy-rs-module-template");
    let build = Command::new(&cargo)
        .arg("build")
        // Not `--offline`: a fresh CI runner has no primed registry cache, so the template's own
        // workspace must be allowed to fetch. `--locked` still pins the exact dependency set.
        .arg("--locked")
        .arg("--manifest-path")
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", &target_dir)
        // CARGO_HOME and the rest of the environment are inherited, so the workspace's offline
        // registry cache is used (the task's test command sets CARGO_HOME).
        .output()
        .unwrap_or_else(|error| panic!("failed to run {cargo:?} for the template: {error}"));
    assert!(
        build.status.success(),
        "template build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let binary = target_dir.join("debug").join("module-template");
    assert!(
        binary.is_file(),
        "template binary not found at {} after a successful build",
        binary.display()
    );

    let mut service = HostService::spawn(
        "template-module",
        ModuleTransportSpec::Stdio {
            program: binary.to_string_lossy().into_owned(),
            args: Vec::new(),
            env: Vec::new(),
            inherit_env: false,
        },
        31,
        config(),
    )
    .expect("template handshake");
    assert!(service.session().granted.contains(Capability::Log));
    let request_id = service
        .open_request(request_head(), 1_000)
        .expect("open request");
    service
        .send_request_body(request_id, b"template works".to_vec())
        .expect("body");
    service
        .end_request(request_id, BridgeHeaders::default())
        .expect("end");

    let mut calls = HostCalls { logs: 0 };
    let mut status = None;
    let mut body = Vec::new();
    let mut template_header = None;
    let mut finished = false;
    for _ in 0..10 {
        match service.next_event(&mut calls).expect("event") {
            HostEvent::HostCallCompleted { .. } => {}
            HostEvent::ResponseHead(head) => {
                status = Some(head.head.status);
                template_header = head
                    .head
                    .headers
                    .iter()
                    .find(|(name, _)| *name == "X-Template")
                    .map(|(_, value)| value.to_string());
            }
            HostEvent::ResponseBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            HostEvent::ResponseEnd(_) => {
                finished = true;
                break;
            }
            other => panic!("unexpected event from template: {other:?}"),
        }
    }
    assert!(finished, "template did not finish the response");
    assert_eq!(status, Some(200));
    assert_eq!(body, b"template works");
    assert_eq!(template_header.as_deref(), Some("caddy-rs-module-template"));
    assert_eq!(
        calls.logs, 1,
        "template should make exactly one log host call"
    );
    assert_eq!(service.stop().expect("stop"), Some(0));
}
