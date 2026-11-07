//! Worked example: a minimal **external** caddy-rs module (T-PLUG-001).
//!
//! This is the runnable example from `docs/PLUGIN-DEVELOPMENT.md`. It speaks the external module
//! protocol over stdin/stdout, so it can be launched by a host that implements
//! `caddy_rs_plug::host::HostService`, or by the crate's `tests/authoring.rs` integration test:
//!
//! ```text
//! # write the binary
//! cargo build -p caddy-rs-plug --bin author_module
//! # exercise it through the reference host (test harness)
//! cargo test --offline --locked -p caddy-rs-plug --test authoring
//! ```
//!
//! What it demonstrates, in the order a host sees it:
//! 1. send `HELLO` with an untrusted descriptor (name, ABI version, requested capabilities, limits);
//! 2. fail closed if the host sends `REJECT`, otherwise accept `HELLO_ACK` (never assume a
//!    capability was granted — use `HELLO_ACK.granted` and handle denials);
//! 3. handle one request kind: echo the request body back, setting `X-Module` and `X-Host-Time`;
//! 4. make two capability-gated host calls inside the request (`log`, then `now`) and handle their
//!    results/errors;
//! 5. end the response with `RESPONSE_END`; exit cleanly on a fatal `ERROR`/`REJECT`/`CANCEL`.
//!
//! The module deliberately has no stdout logging: stdout is the protocol stream. Diagnostics go to
//! stderr (the host may capture it; the reference host sets stderr to `null` by default).
//!
//! Security notes: treat every request field as untrusted data, never assume the host granted a
//! capability just because it was requested, and never try to reach the filesystem or network
//! directly — capabilities only widen the host-call surface.

use std::io::Write;

use caddy_rs_plug::{
    read_frame, write_frame, AbiErrorCode, AbiLimits, AbiVersion, BodyMode, BridgeHeaders,
    Capability, Hello, HostCall, HostCallFrame, HostCallResult, LogLevel, PluginDescriptor,
    PluginLimits, ProtocolFrame, RequestId, ResponseBodyChunk, ResponseEnd, ResponseHead,
    ResponseHeadFrame, PROTOCOL_VERSION,
};

fn main() {
    let limits = AbiLimits::spec_defaults();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    // 1. Handshake: describe the module and what it wants. The descriptor is untrusted input for
    //    the host, and the host's policy is deny-by-default.
    let hello = Hello {
        protocol: PROTOCOL_VERSION,
        descriptor: PluginDescriptor {
            name: "author-example".to_string(),
            abi: AbiVersion::new(1, 0),
            capabilities: vec![Capability::Log.code(), Capability::Clock.code()],
            limits: PluginLimits::default_limits(),
        },
    };
    if write_frame(&mut output, &ProtocolFrame::Hello(hello), &limits).is_err() {
        std::process::exit(3);
    }
    let ack = match read_frame(&mut input, &limits) {
        Ok(ProtocolFrame::HelloAck(ack)) => ack,
        Ok(ProtocolFrame::Reject(reject)) => {
            // Fail closed: the host did not accept this module. Diagnostics on stderr only.
            eprintln!(
                "author_module: host rejected the module (code {}): {}",
                reject.code.code(),
                reject.message
            );
            std::process::exit(2);
        }
        _ => std::process::exit(4),
    };
    let granted = ack.granted;
    let mut log_granted = granted.contains(Capability::Log);
    let mut clock_granted = granted.contains(Capability::Clock);

    // 2. Request loop. A module can be given several requests over one connection.
    let mut body = Vec::new();
    loop {
        let frame = match read_frame(&mut input, &limits) {
            Ok(frame) => frame,
            Err(_) => std::process::exit(0), // host closed the transport
        };
        match frame {
            ProtocolFrame::OpenRequest(_open) => {
                body.clear();
            }
            ProtocolFrame::RequestBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            ProtocolFrame::RequestEnd(end) => {
                let request_id = end.request_id;
                let host_time = host_call_now(
                    &mut input,
                    &mut output,
                    &mut clock_granted,
                    request_id,
                    &limits,
                );
                if log_granted {
                    log_granted = host_call_log(
                        &mut input,
                        &mut output,
                        request_id,
                        format!("author_module handled {} body byte(s)", body.len()),
                        &limits,
                    );
                }
                let response_head = ProtocolFrame::ResponseHead(ResponseHeadFrame {
                    request_id,
                    head: ResponseHead {
                        status: 200,
                        headers: BridgeHeaders::new([
                            ("Content-Type".to_string(), "text/plain".to_string()),
                            ("X-Module".to_string(), "author-example".to_string()),
                            (
                                "X-Host-Time".to_string(),
                                host_time.unwrap_or_else(|| "unavailable".to_string()),
                            ),
                        ])
                        .expect("valid response headers"),
                        body: BodyMode::Streamed,
                    },
                });
                let response_body = ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                    request_id,
                    chunk: body.clone(),
                });
                let response_end = ProtocolFrame::ResponseEnd(ResponseEnd {
                    request_id,
                    trailers: BridgeHeaders::default(),
                });
                for frame in [response_head, response_body, response_end] {
                    if write_frame(&mut output, &frame, &limits).is_err() {
                        std::process::exit(5);
                    }
                }
            }
            ProtocolFrame::HostCallResult(_) | ProtocolFrame::HostCall(_) => {
                // Not expected outside a host-call exchange; ignore to keep the example small.
            }
            ProtocolFrame::Cancel(_) => std::process::exit(0),
            ProtocolFrame::Error(error) => {
                // A fatal connection error is the normal generation-stop path.
                std::process::exit(if error.request_id.is_none() { 0 } else { 14 });
            }
            ProtocolFrame::Reject(reject) => {
                eprintln!(
                    "author_module: rejected (code {}): {}",
                    reject.code.code(),
                    reject.message
                );
                std::process::exit(2);
            }
            _ => std::process::exit(6),
        }
    }
}

/// Make a `Now` host call and read its result. Returns the timestamp as a decimal string for a
/// response header, or `None` when the capability was denied (the module keeps serving).
fn host_call_now(
    input: &mut impl std::io::Read,
    output: &mut impl Write,
    clock_granted: &mut bool,
    request_id: RequestId,
    limits: &AbiLimits,
) -> Option<String> {
    if !*clock_granted {
        return None;
    }
    let call = ProtocolFrame::HostCall(HostCallFrame {
        request_id,
        call: HostCall::Now,
    });
    if write_frame(output, &call, limits).is_err() {
        std::process::exit(5);
    }
    match read_frame(input, limits) {
        Ok(ProtocolFrame::HostCallResult(result)) => match result.result {
            HostCallResult::Now { unix_nanos } => Some(unix_nanos.to_string()),
            _ => None,
        },
        Ok(ProtocolFrame::Error(error)) => {
            if error.code == AbiErrorCode::CapabilityDenied {
                *clock_granted = false;
            }
            None
        }
        _ => None,
    }
}

/// Make a `Log` host call and read its result. Returns `false` if the capability was denied.
fn host_call_log(
    input: &mut impl std::io::Read,
    output: &mut impl Write,
    request_id: RequestId,
    message: String,
    limits: &AbiLimits,
) -> bool {
    let call = ProtocolFrame::HostCall(HostCallFrame {
        request_id,
        call: HostCall::Log {
            level: LogLevel::Info,
            message,
            fields: vec![("module".to_string(), "author-example".to_string())],
        },
    });
    if write_frame(output, &call, limits).is_err() {
        std::process::exit(5);
    }
    match read_frame(input, limits) {
        Ok(ProtocolFrame::HostCallResult(_)) => true,
        Ok(ProtocolFrame::Error(error)) => {
            // A denied log call is not fatal; keep serving the request without logging.
            let _ = error.code;
            false
        }
        _ => false,
    }
}
