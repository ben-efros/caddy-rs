//! Tiny protocol-speaking module used by `crates/plug/tests/host.rs` (T-PLUG-021).
//!
//! It speaks the external module protocol over stdin/stdout. Behaviour is selected with the
//! `PLUG_ECHO_MODE` environment variable:
//!
//! * `echo` (default): handshake, echo each request body back as a 200 response;
//! * `crash`: exit(7) right after the first `OPEN_REQUEST` (crash mid-request);
//! * `oversized`: after the handshake emit a frame whose declared payload exceeds the limit;
//! * `hostcall-clock`: after the response, make a `Now` host call (requires the clock capability
//!   the test host does not grant) and exit(13) when the host denies it with `CapabilityDenied`.
//!
//! This binary is test support, not part of the plugin SDK surface.

use std::io::Write;

use caddy_rs_plug::{
    read_frame, write_frame, AbiErrorCode, AbiLimits, AbiVersion, BodyMode, BridgeHeaders,
    Capability, Hello, HostCall, HostCallFrame, PluginDescriptor, PluginLimits, ProtocolFrame,
    ResponseBodyChunk, ResponseEnd, ResponseHead, ResponseHeadFrame, PROTOCOL_VERSION,
    PROTO_FRAME_ERROR,
};

fn main() {
    let mode = std::env::var("PLUG_ECHO_MODE").unwrap_or_else(|_| "echo".to_string());
    let limits = AbiLimits::spec_defaults();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();

    let hello = Hello {
        protocol: PROTOCOL_VERSION,
        descriptor: PluginDescriptor {
            name: "echo".to_string(),
            abi: AbiVersion::new(1, 0),
            capabilities: vec![Capability::Log.code()],
            limits: PluginLimits::default_limits(),
        },
    };
    if write_frame(&mut output, &ProtocolFrame::Hello(hello), &limits).is_err() {
        std::process::exit(3);
    }
    match read_frame(&mut input, &limits) {
        Ok(ProtocolFrame::HelloAck(_)) => {}
        Ok(ProtocolFrame::Reject(_)) => std::process::exit(2),
        _ => std::process::exit(4),
    }

    if mode == "oversized" {
        // Declared payload far above the 1 MiB frame limit; the host must reject it before reading.
        let _ = output.write_all(&[PROTO_FRAME_ERROR, 0xFF, 0xFF, 0xFF, 0x7F]);
        let _ = output.flush();
        std::process::exit(8);
    }

    let mut body = Vec::new();
    loop {
        let frame = match read_frame(&mut input, &limits) {
            Ok(frame) => frame,
            Err(_) => std::process::exit(0),
        };
        match frame {
            ProtocolFrame::OpenRequest(_open) => {
                body.clear();
                if mode == "crash" {
                    std::process::exit(7);
                }
            }
            ProtocolFrame::RequestBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
            ProtocolFrame::RequestEnd(end) => {
                let id = end.request_id;
                if mode == "hostcall-clock" {
                    let call = ProtocolFrame::HostCall(HostCallFrame {
                        request_id: id,
                        call: HostCall::Now,
                    });
                    if write_frame(&mut output, &call, &limits).is_err() {
                        std::process::exit(5);
                    }
                    match read_frame(&mut input, &limits) {
                        Ok(ProtocolFrame::Error(error)) => {
                            std::process::exit(if error.code == AbiErrorCode::CapabilityDenied {
                                13
                            } else {
                                14
                            });
                        }
                        Ok(ProtocolFrame::HostCallResult(_)) => {}
                        _ => std::process::exit(6),
                    }
                }
                let response_head = ProtocolFrame::ResponseHead(ResponseHeadFrame {
                    request_id: id,
                    head: ResponseHead {
                        status: 200,
                        headers: BridgeHeaders::default(),
                        body: BodyMode::Streamed,
                    },
                });
                let response_body = ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                    request_id: id,
                    chunk: std::mem::take(&mut body),
                });
                let response_end = ProtocolFrame::ResponseEnd(ResponseEnd {
                    request_id: id,
                    trailers: BridgeHeaders::default(),
                });
                for frame in [response_head, response_body, response_end] {
                    if write_frame(&mut output, &frame, &limits).is_err() {
                        std::process::exit(5);
                    }
                }
            }
            ProtocolFrame::Error(error) => {
                if error.request_id.is_none() {
                    // Fatal generation-close: exit cleanly so the host reaps a normal status.
                    std::process::exit(0);
                }
                std::process::exit(if error.code == AbiErrorCode::CapabilityDenied {
                    13
                } else {
                    14
                });
            }
            ProtocolFrame::Cancel(_) => std::process::exit(0),
            ProtocolFrame::HostCallResult(_) => {}
            _ => std::process::exit(6),
        }
    }
}
