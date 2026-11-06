//! Acceptance tests for the plugin host ABI contract.
//!
//! These tests exercise the public surface exactly as a future host (T-PLUG-011) and a plugin SDK
//! would: descriptor validation, version negotiation, capability grants, host-call authorisation,
//! wire round-trips and malformed-input rejection. They double as executable documentation of the
//! version/capability/limit policy.

use caddy_rs_plug::{
    decode_abi_version, encode_abi_version, grant_capabilities, negotiate, AbiError, AbiErrorCode,
    AbiLimits, AbiVersion, BodyBudget, BodyMode, BridgeFrame, BridgeHeaders, BridgeMethod,
    Capability, CapabilityPolicy, CapabilitySet, DescriptorError, HostCall, HostCallContext,
    HostCallError, HostCallResult, LogLevel, NegotiationError, PluginDescriptor, PluginLimits,
    RequestHead, ResponseHead, WireError, ABI_MAJOR, ABI_MINOR, ABI_VERSION, FRAME_ERROR,
    FRAME_HOST_CALL, FRAME_HOST_CALL_RESULT, FRAME_REQUEST_BODY_CHUNK, FRAME_REQUEST_END,
    FRAME_REQUEST_HEAD, FRAME_RESPONSE_BODY_CHUNK, FRAME_RESPONSE_END, FRAME_RESPONSE_HEAD,
    HARD_MAX_MEMORY_BYTES, HARD_MAX_REQUEST_BODY_BYTES, HOST_ABI_VERSION, HOST_CALL_HTTP_REQUEST,
    HOST_CALL_LOG, HOST_CALL_NOW, HOST_CALL_RANDOM, HOST_CALL_READ_CONFIG, MAX_BODY_CHUNK_BYTES,
    MAX_FRAME_PAYLOAD_BYTES, MAX_LOG_MESSAGE_BYTES, MAX_PLUGIN_NAME_LEN, MAX_RANDOM_BYTES,
    MAX_REQUESTED_CAPABILITIES,
};

fn descriptor() -> PluginDescriptor {
    PluginDescriptor {
        name: "example-plugin".to_string(),
        abi: ABI_VERSION,
        capabilities: vec![
            Capability::Log.code(),
            Capability::Clock.code(),
            Capability::Random.code(),
        ],
        limits: PluginLimits::default_limits(),
    }
}

fn limits() -> AbiLimits {
    AbiLimits::spec_defaults()
}

fn headers() -> BridgeHeaders {
    BridgeHeaders::new([
        ("content-type".to_string(), "text/plain".to_string()),
        ("x-test".to_string(), "yes".to_string()),
    ])
    .expect("valid headers")
}

// ---------------------------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------------------------

#[test]
fn exact_compatible_version_is_accepted() {
    let negotiated = negotiate(AbiVersion::new(1, 2), AbiVersion::new(1, 2)).expect("exact match");
    assert_eq!(negotiated.plugin, AbiVersion::new(1, 2));
    assert_eq!(negotiated.host, AbiVersion::new(1, 2));
    assert_eq!(negotiated.effective(), AbiVersion::new(1, 2));
    // The shipped host ABI version negotiates with itself and with an older minor.
    assert!(negotiate(HOST_ABI_VERSION, ABI_VERSION).is_ok());
    assert!(negotiate(HOST_ABI_VERSION, AbiVersion::new(1, 0)).is_ok());
}

#[test]
fn incompatible_major_versions_are_rejected() {
    // Newer plugin major than host.
    assert_eq!(
        negotiate(AbiVersion::new(1, 0), AbiVersion::new(2, 0)),
        Err(NegotiationError::PluginMajorNewer {
            host_major: 1,
            plugin_major: 2
        })
    );
    // Older plugin major than host.
    assert_eq!(
        negotiate(AbiVersion::new(2, 3), AbiVersion::new(1, 9)),
        Err(NegotiationError::HostMajorNewer {
            host_major: 2,
            plugin_major: 1
        })
    );
    // Via the descriptor entry point: typed AbiError.
    let mut newer = descriptor();
    newer.abi = AbiVersion::new(2, 0);
    let error = newer
        .negotiate(ABI_VERSION, &CapabilityPolicy::grant_all_v1())
        .expect_err("major mismatch must fail");
    assert!(matches!(
        error,
        AbiError::Negotiation(NegotiationError::PluginMajorNewer { .. })
    ));
    assert_eq!(error.to_string(), "ABI major version mismatch: plugin requires 2.x but the host implements 1.x (plugin is newer than the host)");
}

#[test]
fn newer_plugin_minor_is_rejected_but_newer_host_minor_is_fine() {
    assert_eq!(
        negotiate(AbiVersion::new(1, 1), AbiVersion::new(1, 2)),
        Err(NegotiationError::PluginMinorNewer {
            host_minor: 1,
            plugin_minor: 2
        })
    );
    let negotiated = negotiate(AbiVersion::new(1, 9), AbiVersion::new(1, 4)).expect("additive");
    assert_eq!(negotiated.effective(), AbiVersion::new(1, 4));
}

#[test]
fn invalid_zero_major_versions_are_rejected() {
    assert_eq!(
        negotiate(AbiVersion::new(0, 1), AbiVersion::new(1, 0)),
        Err(NegotiationError::InvalidVersion { major: 0, minor: 1 })
    );
    let mut invalid = descriptor();
    invalid.abi = AbiVersion::new(0, 0);
    assert_eq!(
        invalid.validate(),
        Err(DescriptorError::InvalidAbiVersion { major: 0, minor: 0 })
    );
}

// ---------------------------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------------------------

#[test]
fn supported_capabilities_are_granted_from_the_policy() {
    let policy = CapabilityPolicy::with_capabilities([Capability::Log, Capability::Clock]);
    let granted = grant_capabilities(&[1, 2], &policy).expect("granted");
    assert_eq!(
        granted,
        CapabilitySet::from_capabilities([Capability::Log, Capability::Clock])
    );
    let negotiated = descriptor()
        .negotiate(
            ABI_VERSION,
            &CapabilityPolicy::with_capabilities([
                Capability::Log,
                Capability::Clock,
                Capability::Random,
            ]),
        )
        .expect("all requested capabilities granted");
    assert_eq!(negotiated.granted.iter().count(), 3);
}

#[test]
fn unsupported_capability_is_rejected() {
    // Unknown code (for example from a future minor version) is a capability error, not ignored.
    let error = grant_capabilities(&[999], &CapabilityPolicy::grant_all_v1())
        .expect_err("unknown capability must be rejected");
    assert!(matches!(
        error,
        caddy_rs_plug::CapabilityError::Unsupported { code: 999 }
    ));
    let mut unsupported = descriptor();
    unsupported.capabilities = vec![999];
    let error = unsupported
        .negotiate(ABI_VERSION, &CapabilityPolicy::grant_all_v1())
        .expect_err("descriptor capability must be rejected");
    assert!(matches!(error, AbiError::Capability(_)));
}

#[test]
fn ungranted_duplicate_and_excessive_capabilities_are_rejected() {
    let denied = descriptor()
        .negotiate(ABI_VERSION, &CapabilityPolicy::deny_all())
        .expect_err("deny-all policy must reject requested capabilities");
    assert!(matches!(denied, AbiError::Capability(_)));

    let duplicate = grant_capabilities(&[1, 1], &CapabilityPolicy::grant_all_v1())
        .expect_err("duplicates must be rejected");
    assert!(matches!(
        duplicate,
        caddy_rs_plug::CapabilityError::Duplicate { code: 1 }
    ));

    let too_many: Vec<u32> = vec![1; MAX_REQUESTED_CAPABILITIES + 1];
    let error = grant_capabilities(&too_many, &CapabilityPolicy::grant_all_v1())
        .expect_err("too many capabilities must be rejected");
    assert!(matches!(
        error,
        caddy_rs_plug::CapabilityError::TooMany { .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// Malformed descriptors
// ---------------------------------------------------------------------------------------------

#[test]
fn malformed_descriptors_are_rejected_with_typed_errors() {
    let cases: Vec<(PluginDescriptor, DescriptorError)> = vec![
        (
            PluginDescriptor {
                name: String::new(),
                ..descriptor()
            },
            DescriptorError::EmptyName,
        ),
        (
            PluginDescriptor {
                name: "x".repeat(MAX_PLUGIN_NAME_LEN + 1),
                ..descriptor()
            },
            DescriptorError::NameTooLong {
                len: MAX_PLUGIN_NAME_LEN + 1,
                max: MAX_PLUGIN_NAME_LEN,
            },
        ),
        (
            PluginDescriptor {
                name: "not a plugin!".to_string(),
                ..descriptor()
            },
            DescriptorError::InvalidNameCharacter { character: ' ' },
        ),
        (
            PluginDescriptor {
                limits: PluginLimits {
                    max_response_body_bytes: 0,
                    ..PluginLimits::default_limits()
                },
                ..descriptor()
            },
            DescriptorError::ZeroLimit {
                field: "limits.max_response_body_bytes",
            },
        ),
        (
            PluginDescriptor {
                limits: PluginLimits {
                    max_request_body_bytes: HARD_MAX_REQUEST_BODY_BYTES + 1,
                    ..PluginLimits::default_limits()
                },
                ..descriptor()
            },
            DescriptorError::LimitTooLarge {
                field: "limits.max_request_body_bytes",
                value: HARD_MAX_REQUEST_BODY_BYTES + 1,
                max: HARD_MAX_REQUEST_BODY_BYTES,
            },
        ),
        (
            PluginDescriptor {
                limits: PluginLimits {
                    max_memory_bytes: HARD_MAX_MEMORY_BYTES + 1,
                    ..PluginLimits::default_limits()
                },
                ..descriptor()
            },
            DescriptorError::LimitTooLarge {
                field: "limits.max_memory_bytes",
                value: HARD_MAX_MEMORY_BYTES + 1,
                max: HARD_MAX_MEMORY_BYTES,
            },
        ),
        (
            PluginDescriptor {
                capabilities: vec![1; MAX_REQUESTED_CAPABILITIES + 1],
                ..descriptor()
            },
            DescriptorError::TooManyCapabilities {
                count: MAX_REQUESTED_CAPABILITIES + 1,
                max: MAX_REQUESTED_CAPABILITIES,
            },
        ),
    ];
    for (descriptor, expected) in cases {
        assert_eq!(descriptor.validate(), Err(expected), "{descriptor:?}");
        assert!(matches!(
            descriptor.negotiate(ABI_VERSION, &CapabilityPolicy::grant_all_v1()),
            Err(AbiError::Descriptor(_))
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Stable codes and wire encodings
// ---------------------------------------------------------------------------------------------

#[test]
fn abi_versions_and_codes_are_stable() {
    assert_eq!(ABI_MAJOR, 1);
    assert_eq!(ABI_MINOR, 0);
    assert_eq!(ABI_VERSION, AbiVersion::new(1, 0));
    assert_eq!(encode_abi_version(ABI_VERSION), vec![1, 0, 0, 0]);
    assert_eq!(
        decode_abi_version(&[1, 0, 0, 0]).expect("decode"),
        ABI_VERSION
    );

    assert_eq!(Capability::Log.code(), 1);
    assert_eq!(Capability::ConfigRead.code(), 5);
    assert_eq!(CapabilitySet::ALL_V1.bits(), 0b1_1111);

    assert_eq!(
        [
            FRAME_REQUEST_HEAD,
            FRAME_REQUEST_BODY_CHUNK,
            FRAME_REQUEST_END
        ],
        [1, 2, 3]
    );
    assert_eq!(
        [
            FRAME_RESPONSE_HEAD,
            FRAME_RESPONSE_BODY_CHUNK,
            FRAME_RESPONSE_END
        ],
        [4, 5, 6]
    );
    assert_eq!(
        [FRAME_HOST_CALL, FRAME_HOST_CALL_RESULT, FRAME_ERROR],
        [7, 8, 9]
    );
    assert_eq!(
        [
            HOST_CALL_LOG,
            HOST_CALL_NOW,
            HOST_CALL_RANDOM,
            HOST_CALL_HTTP_REQUEST,
            HOST_CALL_READ_CONFIG
        ],
        [1, 2, 3, 4, 5]
    );
    assert_eq!(AbiErrorCode::CapabilityDenied.code(), 1000);
    assert_eq!(AbiErrorCode::PluginFailed.code(), 1007);
    assert_eq!(
        AbiErrorCode::from_code(1000),
        Some(AbiErrorCode::CapabilityDenied)
    );
    assert_eq!(AbiErrorCode::from_code(9999), None);
}

#[test]
fn bridging_frames_round_trip_exactly() {
    let limits = limits();
    let frames = vec![
        BridgeFrame::RequestHead(RequestHead {
            method: BridgeMethod::Post,
            scheme: "https".to_string(),
            authority: "example.com".to_string(),
            path_and_query: "/upload?x=1".to_string(),
            headers: headers(),
            body: BodyMode::Streamed,
        }),
        BridgeFrame::RequestBodyChunk(vec![0, 1, 2, 3]),
        BridgeFrame::RequestEnd(headers()),
        BridgeFrame::ResponseHead(ResponseHead {
            status: 201,
            headers: headers(),
            body: BodyMode::Buffered { length: 4 },
        }),
        BridgeFrame::ResponseBodyChunk(vec![4, 5, 6, 7]),
        BridgeFrame::ResponseEnd(BridgeHeaders::default()),
        BridgeFrame::HostCall(HostCall::Log {
            level: LogLevel::Info,
            message: "hello".to_string(),
            fields: vec![("k".to_string(), "v".to_string())],
        }),
        BridgeFrame::HostCallResult(HostCallResult::Random { bytes: vec![9, 8] }),
        BridgeFrame::Error(caddy_rs_plug::AbiErrorFrame {
            code: AbiErrorCode::Cancelled,
            message: "client went away".to_string(),
        }),
    ];
    // Encode each frame and stream-decode the concatenation using the returned byte counts.
    let mut encoded = Vec::new();
    for frame in &frames {
        encoded.extend(frame.encode(&limits).expect("encode frame"));
    }
    let mut offset = 0;
    for expected in &frames {
        let (frame, consumed) = BridgeFrame::decode(&encoded[offset..], &limits).expect("decode");
        assert_eq!(&frame, expected, "frame round-trip");
        offset += consumed;
    }
    assert_eq!(offset, encoded.len());
}

#[test]
fn custom_methods_and_headers_round_trip_and_are_validated() {
    let limits = limits();
    let frame = BridgeFrame::RequestHead(RequestHead {
        method: BridgeMethod::Other("PROPFIND".to_string()),
        scheme: "http".to_string(),
        authority: "localhost".to_string(),
        path_and_query: "/".to_string(),
        headers: BridgeHeaders::new([("depth".to_string(), "1".to_string())]).expect("headers"),
        body: BodyMode::Empty,
    });
    let bytes = frame.encode(&limits).expect("encode");
    let (decoded, _) = BridgeFrame::decode(&bytes, &limits).expect("decode");
    assert_eq!(decoded, frame);

    let mut headers = BridgeHeaders::default();
    assert_eq!(
        headers.push("bad name", "v", &limits),
        Err(WireError::InvalidHeaderName { offset: 0 })
    );
}

#[test]
fn malformed_frames_are_rejected_instead_of_panicking() {
    let limits = limits();
    assert_eq!(
        BridgeFrame::decode(&[], &limits),
        Err(WireError::EmptyFrame)
    );
    // Truncated header/payload.
    assert!(matches!(
        BridgeFrame::decode(&[FRAME_REQUEST_HEAD, 4, 0, 0, 0], &limits),
        Err(WireError::UnexpectedEof { .. })
    ));
    // Unknown tag.
    assert_eq!(
        BridgeFrame::decode(&[0x7F, 0, 0, 0, 0], &limits),
        Err(WireError::UnknownFrameTag { tag: 0x7F })
    );
    // Declared payload above the frame limit.
    assert_eq!(
        BridgeFrame::decode(&[FRAME_REQUEST_BODY_CHUNK, 1, 0, 0x10, 0], &limits),
        Err(WireError::FrameTooLarge {
            len: MAX_FRAME_PAYLOAD_BYTES + 1,
            max: MAX_FRAME_PAYLOAD_BYTES
        })
    );
    // Oversized body chunk relative to a tighter limit.
    let frame = BridgeFrame::RequestBodyChunk(vec![0; MAX_BODY_CHUNK_BYTES + 1]);
    assert!(matches!(
        frame.encode(&limits),
        Err(WireError::LimitExceeded {
            field: "body chunk",
            ..
        })
    ));
    // Invalid UTF-8 in a request head's scheme field.
    let mut payload = Vec::new();
    payload.push(0u8); // GET
    payload.extend_from_slice(&[2, 0, 0, 0, 0xFF, 0xFE]); // scheme length 2, invalid UTF-8
    let mut frame = Vec::new();
    frame.push(FRAME_REQUEST_HEAD);
    frame.extend_from_slice(&u32::try_from(payload.len()).expect("len").to_le_bytes());
    frame.extend_from_slice(&payload);
    assert!(matches!(
        BridgeFrame::decode(&frame, &limits),
        Err(WireError::InvalidUtf8 { .. })
    ));
}

#[test]
fn body_budget_enforces_negotiated_totals() {
    let mut budget = BodyBudget::new(8);
    budget.consume(3).expect("first");
    budget.consume(5).expect("second");
    assert_eq!(budget.remaining(), 0);
    assert!(matches!(
        budget.consume(1),
        Err(WireError::LimitExceeded { .. })
    ));
    // Streamed bodies of unknown length still respect the buffered-head announcement bound.
    let limits = limits();
    let head = BridgeFrame::ResponseHead(ResponseHead {
        status: 200,
        headers: BridgeHeaders::default(),
        body: BodyMode::Buffered {
            length: caddy_rs_plug::MAX_ANNOUNCED_BODY_BYTES + 1,
        },
    });
    assert!(matches!(
        head.encode(&limits),
        Err(WireError::LimitExceeded {
            field: "body length",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------------------------
// Host calls
// ---------------------------------------------------------------------------------------------

#[test]
fn host_calls_are_generation_scoped_and_capability_checked() {
    let limits = limits();
    let granted = CapabilitySet::from_capabilities([Capability::Clock]);
    let mut context = HostCallContext::new(3, granted, 2);
    context
        .authorize(&HostCall::Now, 3, &limits)
        .expect("active generation and granted capability");
    assert_eq!(context.remaining(), 1);
    assert_eq!(
        context.authorize(&HostCall::Now, 4, &limits),
        Err(HostCallError::StaleGeneration {
            call_generation: 3,
            active_generation: 4
        })
    );
    assert_eq!(
        context.authorize(&HostCall::Random { len: 8 }, 3, &limits),
        Err(HostCallError::CapabilityDenied {
            capability: Capability::Random,
            call: HOST_CALL_RANDOM
        })
    );
    context
        .authorize(&HostCall::Now, 3, &limits)
        .expect("budget remaining");
    assert!(matches!(
        context.authorize(&HostCall::Now, 3, &limits),
        Err(HostCallError::CallBudgetExhausted { .. })
    ));
}

#[test]
fn host_call_arguments_respect_limits() {
    let limits = limits();
    assert!(matches!(
        HostCall::Random {
            len: MAX_RANDOM_BYTES + 1
        }
        .validate(&limits),
        Err(HostCallError::InvalidArgument { .. })
    ));
    assert!(matches!(
        HostCall::Log {
            level: LogLevel::Info,
            message: "x".repeat(MAX_LOG_MESSAGE_BYTES + 1),
            fields: Vec::new(),
        }
        .validate(&limits),
        Err(HostCallError::InvalidArgument { .. })
    ));
}

#[test]
fn host_call_payloads_round_trip() {
    let limits = limits();
    let calls = vec![
        HostCall::Log {
            level: LogLevel::Error,
            message: "boom".to_string(),
            fields: vec![("route".to_string(), "/".to_string())],
        },
        HostCall::Now,
        HostCall::Random { len: 4 },
        HostCall::HttpRequest {
            method: BridgeMethod::Get,
            url: "https://example.com/health".to_string(),
            headers: BridgeHeaders::default(),
            body: Vec::new(),
        },
        HostCall::ReadConfig {
            key: "apps.http.servers.srv0.listen".to_string(),
        },
    ];
    for call in calls {
        let mut writer = caddy_rs_plug::Writer::new();
        call.encode(&mut writer, &limits).expect("encode call");
        let encoded = writer.into_vec();
        let mut reader = caddy_rs_plug::Reader::new(&encoded);
        assert_eq!(
            HostCall::decode(&mut reader, &limits).expect("decode"),
            call
        );
        reader.finish().expect("fully consumed");
    }
    let results = vec![
        HostCallResult::Logged,
        HostCallResult::Now {
            unix_nanos: 1_700_000_000_000_000_000,
        },
        HostCallResult::Random {
            bytes: vec![1, 2, 3],
        },
        HostCallResult::HttpResponse {
            status: 204,
            headers: BridgeHeaders::default(),
            body: Vec::new(),
        },
        HostCallResult::ConfigValue { value: None },
    ];
    for result in results {
        let mut writer = caddy_rs_plug::Writer::new();
        result.encode(&mut writer, &limits).expect("encode result");
        let encoded = writer.into_vec();
        let mut reader = caddy_rs_plug::Reader::new(&encoded);
        assert_eq!(
            HostCallResult::decode(&mut reader, &limits).expect("decode"),
            result
        );
        reader.finish().expect("fully consumed");
    }
}

#[test]
fn negotiated_plugin_carries_effective_version_and_limits() {
    let negotiated = descriptor()
        .negotiate(
            AbiVersion::new(1, 5),
            &CapabilityPolicy::with_capabilities([
                Capability::Log,
                Capability::Clock,
                Capability::Random,
            ]),
        )
        .expect("negotiates");
    assert_eq!(negotiated.name, "example-plugin");
    assert_eq!(negotiated.abi.effective(), ABI_VERSION);
    assert_eq!(negotiated.abi.host, AbiVersion::new(1, 5));
    assert_eq!(negotiated.limits, PluginLimits::default_limits());
    assert_eq!(negotiated.granted.iter().count(), 3);
}
