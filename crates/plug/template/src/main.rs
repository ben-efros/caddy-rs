//! Starter external caddy-rs module.
//!
//! Copy this directory, rename the package/binary, and replace the descriptor + request handler.
//! The module speaks the external module protocol over stdin/stdout; the host launches it with
//! piped stdio (or connects it to a Unix socket) and performs the handshake.
//!
//! Run it through the reference host:
//!   cargo test --offline --locked --manifest-path crates/plug/template/Cargo.toml
//! (the caddy-rs integration test `crates/plug/tests/template.rs` does the same from the main repo).

use caddy_rs_plug::{
    read_frame, write_frame, AbiErrorCode, AbiLimits, AbiVersion, BodyMode, BridgeHeaders,
    Capability, Hello, HostCall, HostCallFrame, HostCallResult, LogLevel, PluginDescriptor,
    PluginLimits, ProtocolFrame, ResponseBodyChunk, ResponseEnd, ResponseHead, ResponseHeadFrame,
    PROTOCOL_VERSION,
};

fn main() {
    let limits = AbiLimits::spec_defaults();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    // 1. Describe the module. `capabilities` is a request, not a grant: the host's policy decides.
    //    Keep the list minimal; the template asks for `log` only.
    let hello = Hello {
        protocol: PROTOCOL_VERSION,
        descriptor: PluginDescriptor {
            name: "template-module".to_string(),
            abi: AbiVersion::new(1, 0),
            capabilities: vec![Capability::Log.code()],
            limits: PluginLimits::default_limits(),
        },
    };
    if write_frame(&mut output, &ProtocolFrame::Hello(hello), &limits).is_err() {
        std::process::exit(3);
    }

    let ack = match read_frame(&mut input, &limits) {
        Ok(ProtocolFrame::HelloAck(ack)) => ack,
        Ok(ProtocolFrame::Reject(reject)) => {
            eprintln!(
                "template-module: host rejected the module (code {}): {}",
                reject.code.code(),
                reject.message
            );
            std::process::exit(2);
        }
        _ => std::process::exit(4),
    };
    // Never assume the capability was granted — check the ACK. A denied host call is recoverable.
    let mut log_granted = ack.granted.contains(Capability::Log);

    // 2. Serve requests until the host closes the connection or cancels.
    let mut body = Vec::new();
    loop {
        let frame = match read_frame(&mut input, &limits) {
            Ok(frame) => frame,
            Err(_) => std::process::exit(0),
        };
        match frame {
            ProtocolFrame::OpenRequest(_open) => body.clear(),
            ProtocolFrame::RequestBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            ProtocolFrame::RequestEnd(end) => {
                let request_id = end.request_id;

                // One capability-gated host call: log the request size. If the host denies it,
                // continue serving the request; logging is optional for this template.
                if log_granted {
                    let call = ProtocolFrame::HostCall(HostCallFrame {
                        request_id,
                        call: HostCall::Log {
                            level: LogLevel::Info,
                            message: format!(
                                "template-module handled a {} byte request",
                                body.len()
                            ),
                            fields: vec![("module".to_string(), "template-module".to_string())],
                        },
                    });
                    if write_frame(&mut output, &call, &limits).is_err() {
                        std::process::exit(5);
                    }
                    match read_frame(&mut input, &limits) {
                        Ok(ProtocolFrame::HostCallResult(result)) => match result.result {
                            HostCallResult::Logged => {}
                            _ => {}
                        },
                        Ok(ProtocolFrame::Error(error)) => {
                            if error.code == AbiErrorCode::CapabilityDenied {
                                log_granted = false;
                            }
                        }
                        _ => {}
                    }
                }

                let head = ProtocolFrame::ResponseHead(ResponseHeadFrame {
                    request_id,
                    head: ResponseHead {
                        status: 200,
                        headers: BridgeHeaders::new([(
                            "X-Template".to_string(),
                            "caddy-rs-module-template".to_string(),
                        )])
                        .expect("valid header"),
                        body: BodyMode::Streamed,
                    },
                });
                let chunk = ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                    request_id,
                    chunk: body.clone(),
                });
                let end = ProtocolFrame::ResponseEnd(ResponseEnd {
                    request_id,
                    trailers: BridgeHeaders::default(),
                });
                for frame in [head, chunk, end] {
                    if write_frame(&mut output, &frame, &limits).is_err() {
                        std::process::exit(5);
                    }
                }
            }
            ProtocolFrame::Cancel(_) => std::process::exit(0),
            ProtocolFrame::Error(error) => {
                // Fatal connection close (generation stop) or request-scoped host error.
                std::process::exit(if error.request_id.is_none() { 0 } else { 14 });
            }
            _ => {}
        }
    }
}
