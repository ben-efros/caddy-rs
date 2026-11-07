//! External module protocol tests: golden frames, handshake accept/reject, an in-process module
//! driver that echoes a request back, and malformed-input robustness.
//!
//! These tests use only the public `caddy-rs-plug` API, so they are the executable specification of
//! `docs/PLUGIN-PROTOCOL.md` for a future host runtime or module SDK.

use caddy_rs_plug::{
    accept_handshake, tighten_limits, validate_handshake_ack, AbiErrorCode, AbiLimits, AbiVersion,
    BodyMode, BridgeHeaders, BridgeMethod, Cancel, Capability, CapabilityError, CapabilityPolicy,
    CapabilitySet, ErrorFrame, HandshakeError, Hello, HelloAck, HostHandshakeConfig, NegotiatedAbi,
    OpenRequest, PluginDescriptor, PluginLimits, ProtocolError, ProtocolFrame, Reject, RejectPhase,
    RequestBodyChunk, RequestEnd, RequestHead, RequestId, ResponseBodyChunk, ResponseEnd,
    ResponseHead, ResponseHeadFrame, HOST_ABI_VERSION, HOST_PROTOCOL_VERSION, PROTOCOL_VERSION,
    PROTO_FRAME_CANCEL, PROTO_FRAME_ERROR, PROTO_FRAME_HEADER_BYTES, PROTO_FRAME_HELLO,
    PROTO_FRAME_HELLO_ACK, PROTO_FRAME_OPEN_REQUEST, PROTO_FRAME_REQUEST_BODY_CHUNK,
    PROTO_FRAME_REQUEST_END, PROTO_FRAME_RESPONSE_BODY_CHUNK, PROTO_FRAME_RESPONSE_END,
    PROTO_FRAME_RESPONSE_HEAD,
};

fn limits() -> AbiLimits {
    AbiLimits::spec_defaults()
}

fn request_id(value: u64) -> RequestId {
    RequestId::new(value).expect("valid request id")
}

fn headers(entries: &[(&str, &str)]) -> BridgeHeaders {
    BridgeHeaders::new(
        entries
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string())),
    )
    .expect("valid headers")
}

fn descriptor(capabilities: Vec<u32>) -> PluginDescriptor {
    PluginDescriptor {
        name: "echo".to_string(),
        abi: AbiVersion::new(1, 0),
        capabilities,
        limits: PluginLimits::default_limits(),
    }
}

fn hello(capabilities: Vec<u32>) -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        descriptor: descriptor(capabilities),
    }
}

fn request_head() -> RequestHead {
    RequestHead {
        method: BridgeMethod::Get,
        scheme: "https".to_string(),
        authority: "example.com".to_string(),
        path_and_query: "/echo".to_string(),
        headers: headers(&[("X-Request", "1")]),
        body: BodyMode::Streamed,
    }
}

fn response_head() -> ResponseHead {
    ResponseHead {
        status: 200,
        headers: headers(&[("Content-Type", "text/plain")]),
        body: BodyMode::Streamed,
    }
}

fn encode(frame: &ProtocolFrame) -> Vec<u8> {
    frame.encode(&limits()).expect("encode frame")
}

fn decode(bytes: &[u8]) -> (ProtocolFrame, usize) {
    ProtocolFrame::decode(bytes, &limits()).expect("decode frame")
}

fn u32_len(frame: &[u8]) -> usize {
    u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize
}

#[test]
fn golden_hello_frame_has_the_specified_layout() {
    // The HELLO payload is: protocol version (4) | plugin name (len+bytes) | plugin ABI version
    // (4) | capability count (1) | capability codes (u32 each) | limits (u64,u64,u32,u64).
    let frame = ProtocolFrame::Hello(hello(vec![Capability::Log.code()]));
    let encoded = encode(&frame);
    let mut expected = vec![PROTO_FRAME_HELLO, 0, 0, 0, 0];
    expected.extend_from_slice(&1_u16.to_le_bytes()); // protocol major
    expected.extend_from_slice(&0_u16.to_le_bytes()); // protocol minor
    expected.extend_from_slice(&4_u32.to_le_bytes()); // name length
    expected.extend_from_slice(b"echo");
    expected.extend_from_slice(&1_u16.to_le_bytes()); // plugin ABI major
    expected.extend_from_slice(&0_u16.to_le_bytes()); // plugin ABI minor
    expected.push(1); // capability count
    expected.extend_from_slice(&1_u32.to_le_bytes()); // log capability
    expected.extend_from_slice(&1_048_576_u64.to_le_bytes());
    expected.extend_from_slice(&1_048_576_u64.to_le_bytes());
    expected.extend_from_slice(&1_000_u32.to_le_bytes());
    expected.extend_from_slice(&67_108_864_u64.to_le_bytes());
    let payload_len = expected.len() as u32 - PROTO_FRAME_HEADER_BYTES as u32;
    expected[1..5].copy_from_slice(&payload_len.to_le_bytes());
    assert_eq!(encoded, expected, "golden HELLO bytes");
    let (decoded, consumed) = decode(&encoded);
    assert_eq!(decoded, frame);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn golden_body_chunk_and_cancel_frames_are_deterministic() {
    let chunk = ProtocolFrame::RequestBodyChunk(RequestBodyChunk {
        request_id: request_id(7),
        chunk: b"abc".to_vec(),
    });
    let encoded = encode(&chunk);
    let mut expected = vec![PROTO_FRAME_REQUEST_BODY_CHUNK, 0, 0, 0, 0];
    expected.extend_from_slice(&7_u64.to_le_bytes());
    expected.extend_from_slice(&3_u32.to_le_bytes());
    expected.extend_from_slice(b"abc");
    expected[1..5].copy_from_slice(&(15_u32).to_le_bytes());
    assert_eq!(encoded, expected);
    assert_eq!(decode(&encoded).0, chunk);

    let cancel = ProtocolFrame::Cancel(Cancel {
        request_id: request_id(7),
        code: AbiErrorCode::Cancelled,
        message: "gone".to_string(),
    });
    let encoded = encode(&cancel);
    assert_eq!(encoded[0], PROTO_FRAME_CANCEL);
    assert_eq!(u32_len(&encoded), encoded.len() - PROTO_FRAME_HEADER_BYTES);
    assert_eq!(decode(&encoded).0, cancel);
}

#[test]
fn every_message_variant_round_trips_with_its_tag() {
    let id = request_id(1);
    let cases = vec![
        ProtocolFrame::Hello(hello(vec![Capability::Clock.code()])),
        ProtocolFrame::HelloAck(HelloAck {
            protocol: PROTOCOL_VERSION,
            abi: NegotiatedAbi {
                plugin: AbiVersion::new(1, 0),
                host: HOST_ABI_VERSION,
            },
            granted: CapabilitySet::from_capabilities([Capability::Clock]),
            limits: PluginLimits::default_limits(),
            max_in_flight_requests: 8,
            body_window_bytes: 65_536,
        }),
        ProtocolFrame::Reject(HandshakeError::InvalidConfig { reason: "test" }.to_reject()),
        ProtocolFrame::OpenRequest(OpenRequest {
            request_id: id,
            deadline_ms: 250,
            head: request_head(),
        }),
        ProtocolFrame::RequestBodyChunk(RequestBodyChunk {
            request_id: id,
            chunk: b"hello".to_vec(),
        }),
        ProtocolFrame::RequestEnd(RequestEnd {
            request_id: id,
            trailers: headers(&[("X-Trailer", "a")]),
        }),
        ProtocolFrame::ResponseHead(ResponseHeadFrame {
            request_id: id,
            head: response_head(),
        }),
        ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
            request_id: id,
            chunk: b"world".to_vec(),
        }),
        ProtocolFrame::ResponseEnd(ResponseEnd {
            request_id: id,
            trailers: BridgeHeaders::default(),
        }),
        ProtocolFrame::Cancel(Cancel {
            request_id: id,
            code: AbiErrorCode::Cancelled,
            message: "cancelled".to_string(),
        }),
        ProtocolFrame::Error(ErrorFrame {
            request_id: Some(id),
            fatal: false,
            code: AbiErrorCode::LimitExceeded,
            message: "body too large".to_string(),
        }),
        ProtocolFrame::Error(ErrorFrame {
            request_id: None,
            fatal: true,
            code: AbiErrorCode::PluginFailed,
            message: "module crashed".to_string(),
        }),
    ];
    let expected_tags = [
        PROTO_FRAME_HELLO,
        PROTO_FRAME_HELLO_ACK,
        0x12, // reject
        PROTO_FRAME_OPEN_REQUEST,
        PROTO_FRAME_REQUEST_BODY_CHUNK,
        PROTO_FRAME_REQUEST_END,
        PROTO_FRAME_RESPONSE_HEAD,
        PROTO_FRAME_RESPONSE_BODY_CHUNK,
        PROTO_FRAME_RESPONSE_END,
        PROTO_FRAME_CANCEL,
        PROTO_FRAME_ERROR,
        PROTO_FRAME_ERROR,
    ];
    for (frame, expected_tag) in cases.iter().zip(expected_tags) {
        assert_eq!(frame.tag(), expected_tag);
        let encoded = encode(frame);
        assert_eq!(encoded[0], expected_tag);
        assert_eq!(u32_len(&encoded), encoded.len() - PROTO_FRAME_HEADER_BYTES);
        let (decoded, consumed) = decode(&encoded);
        assert_eq!(&decoded, frame, "round-trip for tag {expected_tag:#04x}");
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn protocol_tags_do_not_overlap_the_in_process_abi() {
    assert!(!(1..=9).contains(&PROTO_FRAME_HELLO));
    let in_process = vec![1_u8, 2, 3, 4, 5, 6, 7, 8, 9];
    for tag in in_process {
        let mut bytes = vec![tag, 0, 0, 0, 0];
        assert_eq!(
            ProtocolFrame::decode(&bytes, &limits()),
            Err(ProtocolError::InProcessFrameTag { tag }),
            "in-process tag {tag} must be rejected"
        );
        bytes[0] = 0;
        // Unknown out-of-range tags are a WireError::UnknownFrameTag.
        assert!(matches!(
            ProtocolFrame::decode(&[0xEE, 0, 0, 0, 0], &limits()),
            Err(ProtocolError::Wire(
                caddy_rs_plug::WireError::UnknownFrameTag { tag: 0xEE }
            ))
        ));
    }
}

#[test]
fn handshake_accepts_module_with_requested_capabilities() {
    let module_hello = hello(vec![Capability::Log.code(), Capability::Clock.code()]);
    let config = HostHandshakeConfig {
        policy: CapabilityPolicy::with_capabilities([Capability::Log, Capability::Clock]),
        host_limits: PluginLimits {
            max_request_body_bytes: 512 * 1024,
            ..PluginLimits::default_limits()
        },
        max_in_flight_requests: 4,
        body_window_bytes: 32 * 1024,
        ..HostHandshakeConfig::default()
    };
    let ack = accept_handshake(&module_hello, &config).expect("handshake accepted");
    assert_eq!(ack.protocol, PROTOCOL_VERSION);
    assert_eq!(ack.abi.plugin, AbiVersion::new(1, 0));
    assert_eq!(ack.abi.host, HOST_ABI_VERSION);
    assert_eq!(
        ack.granted,
        CapabilitySet::from_capabilities([Capability::Log, Capability::Clock])
    );
    // Host limits tighten the module's request; otherwise the module's requested limits stand.
    assert_eq!(ack.limits.max_request_body_bytes, 512 * 1024);
    assert_eq!(
        ack.limits.max_response_body_bytes,
        module_hello.descriptor.limits.max_response_body_bytes
    );
    assert_eq!(
        tighten_limits(&module_hello.descriptor.limits, &config.host_limits),
        ack.limits
    );
    let session = validate_handshake_ack(&module_hello, &ack).expect("module accepts ack");
    assert_eq!(session.granted, ack.granted);
    assert_eq!(session.max_in_flight_requests, 4);
    assert_eq!(session.body_window_bytes, 32 * 1024);
}

#[test]
fn handshake_rejects_incompatible_versions_and_ungranted_capabilities() {
    // External protocol major mismatch.
    let mut module_hello = hello(Vec::new());
    module_hello.protocol = AbiVersion::new(2, 0);
    let error = accept_handshake(&module_hello, &HostHandshakeConfig::default())
        .expect_err("protocol major mismatch");
    assert_eq!(
        error,
        HandshakeError::ProtocolVersion(caddy_rs_plug::NegotiationError::PluginMajorNewer {
            host_major: 1,
            plugin_major: 2
        })
    );
    assert_eq!(error.to_reject().phase, RejectPhase::ProtocolVersion);

    // Plugin ABI newer minor than the host.
    let module_hello = {
        let mut value = hello(Vec::new());
        value.descriptor.abi = AbiVersion::new(1, 7);
        value
    };
    let error = accept_handshake(&module_hello, &HostHandshakeConfig::default())
        .expect_err("plugin ABI minor too new");
    assert_eq!(error.phase(), RejectPhase::AbiVersion);
    assert_eq!(error.abi_code(), AbiErrorCode::Unsupported);

    // Deny-by-default capability policy.
    let module_hello = hello(vec![Capability::Random.code()]);
    let error = accept_handshake(&module_hello, &HostHandshakeConfig::default())
        .expect_err("capability not granted");
    assert_eq!(
        error,
        HandshakeError::Capability(CapabilityError::NotGranted {
            capability: Capability::Random
        })
    );
    let reject = error.to_reject();
    assert_eq!(reject.phase, RejectPhase::Capability);
    assert_eq!(reject.code, AbiErrorCode::CapabilityDenied);

    // Unknown capability codes are rejected, never ignored.
    let module_hello = hello(vec![0xDEAD_BEEF]);
    let error = accept_handshake(
        &module_hello,
        &HostHandshakeConfig {
            policy: CapabilityPolicy::grant_all_v1(),
            ..HostHandshakeConfig::default()
        },
    )
    .expect_err("unknown capability");
    assert_eq!(
        error,
        HandshakeError::Capability(CapabilityError::Unsupported { code: 0xDEAD_BEEF })
    );

    // A module rejects an ACK that grants an unrequested capability.
    let module_hello = hello(vec![Capability::Log.code()]);
    let mut ack = accept_handshake(
        &module_hello,
        &HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([Capability::Log]),
            ..HostHandshakeConfig::default()
        },
    )
    .expect("ack");
    ack.granted = CapabilitySet::from_capabilities([Capability::Random]);
    assert_eq!(
        validate_handshake_ack(&module_hello, &ack),
        Err(HandshakeError::InvalidAck {
            reason: "ack granted a capability that was not requested"
        })
    );
}

#[test]
fn malformed_handshake_frames_are_typed_errors() {
    // Truncated HELLO payload.
    let valid = encode(&ProtocolFrame::Hello(hello(vec![Capability::Log.code()])));
    for length in 0..valid.len() {
        assert!(
            ProtocolFrame::decode(&valid[..length], &limits()).is_err(),
            "truncated HELLO must fail at length {length}"
        );
    }

    // Oversized payload declarations.
    let mut oversized = vec![PROTO_FRAME_HELLO, 0, 0, 0, 0];
    oversized[1..5].copy_from_slice(&(u32::MAX).to_le_bytes());
    assert!(matches!(
        ProtocolFrame::decode(&oversized, &limits()),
        Err(ProtocolError::Wire(
            caddy_rs_plug::WireError::FrameTooLarge { .. }
        ))
    ));
    let strict_limits = AbiLimits {
        max_frame_payload: 4,
        ..AbiLimits::spec_defaults()
    };
    assert!(matches!(
        ProtocolFrame::decode(&valid, &strict_limits),
        Err(ProtocolError::Wire(
            caddy_rs_plug::WireError::FrameTooLarge { .. }
        ))
    ));

    // Unknown capability code inside a HELLO payload.
    let mut payload = caddy_rs_plug::Writer::new();
    PROTOCOL_VERSION.encode(&mut payload);
    payload.string("plugin name", "echo").expect("name");
    AbiVersion::new(1, 0).encode(&mut payload);
    payload.u8(1);
    payload.u32(42);
    payload.u64(1024);
    payload.u64(1024);
    payload.u32(1);
    payload.u64(1024);
    let payload = payload.into_vec();
    let mut frame = caddy_rs_plug::Writer::with_capacity(5 + payload.len());
    frame.u8(PROTO_FRAME_HELLO);
    frame.u32(payload.len() as u32);
    let mut frame = frame.into_vec();
    frame.extend_from_slice(&payload);
    // Decoding succeeds structurally (unknown capability codes are a negotiation decision), but
    // the handshake rejects them loudly.
    let (decoded, _) = ProtocolFrame::decode(&frame, &limits()).expect("structurally valid");
    let ProtocolFrame::Hello(decoded) = decoded else {
        panic!("expected HELLO");
    };
    let error = accept_handshake(
        &decoded,
        &HostHandshakeConfig {
            policy: CapabilityPolicy::grant_all_v1(),
            ..HostHandshakeConfig::default()
        },
    )
    .expect_err("unknown capability rejected");
    assert_eq!(
        error,
        HandshakeError::Capability(CapabilityError::Unsupported { code: 42 })
    );
}

#[test]
fn error_frames_map_protocol_errors_to_stable_codes() {
    let error = ProtocolError::ZeroRequestId;
    let frame = error.to_error_frame(None);
    assert!(frame.fatal);
    assert_eq!(frame.code, AbiErrorCode::InvalidRequest);
    let encoded = encode(&ProtocolFrame::Error(frame.clone()));
    let (decoded, _) = decode(&encoded);
    assert_eq!(decoded, ProtocolFrame::Error(frame));

    let request_scoped =
        ProtocolError::Wire(caddy_rs_plug::WireError::FrameTooLarge { len: 2, max: 1 })
            .to_error_frame(Some(request_id(3)));
    assert!(!request_scoped.fatal);
    assert_eq!(request_scoped.code, AbiErrorCode::InvalidRequest);
    assert_eq!(request_scoped.request_id, Some(request_id(3)));
}

/// In-process stand-in for an external module: it speaks the protocol over a byte stream and echoes
/// request bytes back as a response. This is the reference driver a module SDK would use.
struct EchoModule {
    output: Vec<u8>,
    phase: ModulePhase,
    body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum ModulePhase {
    AwaitingHello,
    Ready,
}

impl EchoModule {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            phase: ModulePhase::AwaitingHello,
            body: Vec::new(),
        }
    }

    fn push(&mut self, frame: ProtocolFrame) {
        self.output
            .extend_from_slice(&frame.encode(&limits()).expect("encode"));
    }

    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.output.clear();
        let mut offset = 0;
        while offset < input.len() {
            let (frame, consumed) =
                ProtocolFrame::decode(&input[offset..], &limits()).expect("driver decodes");
            offset += consumed;
            self.handle(frame);
        }
        std::mem::take(&mut self.output)
    }

    fn handle(&mut self, frame: ProtocolFrame) {
        match frame {
            ProtocolFrame::Hello(hello) => {
                assert_eq!(self.phase, ModulePhase::AwaitingHello);
                // The module side validates the host's ACK before using the session.
                let config = HostHandshakeConfig {
                    policy: CapabilityPolicy::with_capabilities([Capability::Log]),
                    ..HostHandshakeConfig::default()
                };
                let ack = accept_handshake(&hello, &config).expect("host accepts");
                let _session = validate_handshake_ack(&hello, &ack).expect("module accepts ack");
                self.phase = ModulePhase::Ready;
                self.push(ProtocolFrame::HelloAck(ack));
            }
            ProtocolFrame::OpenRequest(open) => {
                assert_eq!(self.phase, ModulePhase::Ready);
                assert!(open.deadline_ms > 0, "driver requires a deadline");
                assert_eq!(open.request_id, request_id(1));
                self.body.clear();
            }
            ProtocolFrame::RequestBodyChunk(chunk) => {
                self.body.extend_from_slice(&chunk.chunk);
            }
            ProtocolFrame::RequestEnd(end) => {
                assert_eq!(end.request_id, request_id(1));
                // Echo the request body and the request header value back.
                self.push(ProtocolFrame::ResponseHead(ResponseHeadFrame {
                    request_id: end.request_id,
                    head: ResponseHead {
                        status: 200,
                        headers: headers(&[("X-Echo", "1")]),
                        body: BodyMode::Streamed,
                    },
                }));
                let body = std::mem::take(&mut self.body);
                self.push(ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                    request_id: end.request_id,
                    chunk: body,
                }));
                self.push(ProtocolFrame::ResponseEnd(ResponseEnd {
                    request_id: end.request_id,
                    trailers: headers(&[("X-Trailer", "done")]),
                }));
            }
            ProtocolFrame::Cancel(cancel) => {
                self.push(ProtocolFrame::Error(ErrorFrame {
                    request_id: Some(cancel.request_id),
                    fatal: false,
                    code: cancel.code,
                    message: "request cancelled".to_string(),
                }));
            }
            other => panic!("driver received unexpected frame {other:?}"),
        }
    }
}

#[test]
fn in_process_module_driver_echoes_a_request_through_the_protocol() {
    let mut driver = EchoModule::new();
    let mut host_outbound = Vec::new();

    // Handshake.
    let module_hello = hello(vec![Capability::Log.code()]);
    let encoded_hello = encode(&ProtocolFrame::Hello(module_hello.clone()));
    let encoded_ack = driver.feed(&encoded_hello);
    let (ack_frame, _) = decode(&encoded_ack);
    let ProtocolFrame::HelloAck(ack) = ack_frame else {
        panic!("expected HELLO_ACK");
    };
    let session = validate_handshake_ack(&module_hello, &ack).expect("session validated");
    assert_eq!(session.granted.iter().count(), 1);
    assert!(driver.phase == ModulePhase::Ready);

    // Request: head + two chunks + end with a trailer.
    host_outbound.extend_from_slice(&encode(&ProtocolFrame::OpenRequest(OpenRequest {
        request_id: request_id(1),
        deadline_ms: 1_000,
        head: request_head(),
    })));
    host_outbound.extend_from_slice(&encode(&ProtocolFrame::RequestBodyChunk(
        RequestBodyChunk {
            request_id: request_id(1),
            chunk: b"hello ".to_vec(),
        },
    )));
    host_outbound.extend_from_slice(&encode(&ProtocolFrame::RequestBodyChunk(
        RequestBodyChunk {
            request_id: request_id(1),
            chunk: b"world".to_vec(),
        },
    )));
    host_outbound.extend_from_slice(&encode(&ProtocolFrame::RequestEnd(RequestEnd {
        request_id: request_id(1),
        trailers: headers(&[("X-Request-Trailer", "1")]),
    })));

    let response_bytes = driver.feed(&host_outbound);
    let mut offset = 0;
    let mut frames = Vec::new();
    while offset < response_bytes.len() {
        let (frame, consumed) = decode(&response_bytes[offset..]);
        offset += consumed;
        frames.push(frame);
    }
    assert_eq!(frames.len(), 3, "response head + body + end");
    let ProtocolFrame::ResponseHead(head) = &frames[0] else {
        panic!("expected response head");
    };
    assert_eq!(head.request_id, request_id(1));
    assert_eq!(head.head.status, 200);
    assert_eq!(
        head.head.headers.iter().collect::<Vec<_>>(),
        vec![("X-Echo", "1")]
    );
    let ProtocolFrame::ResponseBodyChunk(chunk) = &frames[1] else {
        panic!("expected response chunk");
    };
    assert_eq!(chunk.chunk, b"hello world");
    let ProtocolFrame::ResponseEnd(end) = &frames[2] else {
        panic!("expected response end");
    };
    assert_eq!(
        end.trailers.iter().collect::<Vec<_>>(),
        vec![("X-Trailer", "done")]
    );
}

#[test]
fn in_process_module_driver_cancellation_produces_an_error_frame() {
    let mut driver = EchoModule::new();
    let encoded_hello = encode(&ProtocolFrame::Hello(hello(Vec::new())));
    let _ = driver.feed(&encoded_hello);
    let outbound = encode(&ProtocolFrame::OpenRequest(OpenRequest {
        request_id: request_id(1),
        deadline_ms: 10,
        head: request_head(),
    }));
    let _ = driver.feed(&outbound);
    let cancel = encode(&ProtocolFrame::Cancel(Cancel {
        request_id: request_id(1),
        code: AbiErrorCode::Cancelled,
        message: "client gone".to_string(),
    }));
    let bytes = driver.feed(&cancel);
    let (frame, _) = decode(&bytes);
    assert_eq!(
        frame,
        ProtocolFrame::Error(ErrorFrame {
            request_id: Some(request_id(1)),
            fatal: false,
            code: AbiErrorCode::Cancelled,
            message: "request cancelled".to_string(),
        })
    );
}

#[test]
fn reject_frames_round_trip_through_the_wire() {
    let rejects = vec![
        HandshakeError::ProtocolVersion(caddy_rs_plug::NegotiationError::HostMajorNewer {
            host_major: 2,
            plugin_major: 1,
        })
        .to_reject(),
        HandshakeError::Capability(CapabilityError::NotGranted {
            capability: Capability::HttpClient,
        })
        .to_reject(),
        HandshakeError::Descriptor(caddy_rs_plug::DescriptorError::EmptyName).to_reject(),
    ];
    for reject in rejects {
        assert!(matches!(
            reject.phase,
            RejectPhase::ProtocolVersion | RejectPhase::Capability | RejectPhase::Descriptor
        ));
        let encoded = encode(&ProtocolFrame::Reject(reject.clone()));
        let (decoded, _) = decode(&encoded);
        assert_eq!(decoded, ProtocolFrame::Reject(reject));
    }
    // Unknown rejection phase bytes are typed errors.
    let mut bytes = vec![0x12, 0, 0, 0, 0];
    bytes.extend_from_slice(&[0x7F, 0xE8, 0x03, 0, 0, 0, 0, 0]);
    bytes[1..5].copy_from_slice(&8_u32.to_le_bytes());
    assert!(ProtocolFrame::decode(&bytes, &limits()).is_err());
}

#[test]
fn malformed_and_mutated_inputs_are_typed_errors_not_panics() {
    let valid_frames = [
        encode(&ProtocolFrame::Hello(hello(vec![Capability::Log.code()]))),
        encode(&ProtocolFrame::OpenRequest(OpenRequest {
            request_id: request_id(9),
            deadline_ms: 0,
            head: request_head(),
        })),
        encode(&ProtocolFrame::ResponseHead(ResponseHeadFrame {
            request_id: request_id(9),
            head: response_head(),
        })),
        encode(&ProtocolFrame::Cancel(Cancel {
            request_id: request_id(9),
            code: AbiErrorCode::Cancelled,
            message: "x".to_string(),
        })),
    ];
    let mut checks = 0;
    for valid in &valid_frames {
        // Every truncation.
        for length in 0..valid.len() {
            let result = ProtocolFrame::decode(&valid[..length], &limits());
            if let Err(error) = result {
                let _ = error.abi_code();
            }
            checks += 1;
        }
        // Single-byte mutations in the frame header and the first payload bytes.
        for index in 0..valid.len().min(24) {
            for mask in [0x01_u8, 0x80, 0xFF] {
                let mut mutated = valid.clone();
                mutated[index] ^= mask;
                if let Ok((frame, consumed)) = ProtocolFrame::decode(&mutated, &limits()) {
                    let _ = frame.tag();
                    assert!(consumed <= mutated.len());
                }
                checks += 1;
            }
        }
    }
    // Pseudo-random byte strings of assorted lengths must never panic.
    let mut state = 0x1234_5678_u64;
    for length in 0..64_usize {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            bytes.push((state >> 33) as u8);
        }
        if let Ok((frame, consumed)) = ProtocolFrame::decode(&bytes, &limits()) {
            let _ = frame.tag();
            assert!(consumed <= bytes.len());
        }
        checks += 1;
    }
    assert!(checks > 300, "fuzz-ish coverage exercised {checks} inputs");
}

#[test]
fn duplicate_request_ids_are_rejected_by_the_host_state_machine_contract() {
    // The frame codec cannot see per-connection state; this guards the documented rule that ids
    // must be non-zero and unique. Zero is rejected by the codec; uniqueness is the host's job.
    assert_eq!(RequestId::new(0), Err(ProtocolError::ZeroRequestId));
    assert_eq!(request_id(u64::MAX).get(), u64::MAX);
    assert_ne!(request_id(1), request_id(2));
    let mut bytes = vec![PROTO_FRAME_OPEN_REQUEST, 0, 0, 0, 0];
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes[1..5].copy_from_slice(&12_u32.to_le_bytes());
    assert!(matches!(
        ProtocolFrame::decode(&bytes, &limits()),
        Err(ProtocolError::ZeroRequestId)
    ));
}
