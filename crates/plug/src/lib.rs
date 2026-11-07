//! Versioned WebAssembly plugin host ABI for caddy-rs.
//!
//! This crate is the **contract** between the caddy-rs plugin host and third-party WebAssembly
//! plugins (ADR-0006): version negotiation, capability grants, host calls and the HTTP
//! request/response bridging format. It deliberately contains no runtime and no external
//! dependencies beyond `serde` for the descriptor data model: embedding a WASM engine is a
//! separate task (T-PLUG-011), and this crate must stay pure so both sides can share it.
//!
//! # Security model
//!
//! * **No ambient authority.** A plugin gets no filesystem, network, clock or randomness access by
//!   default. It asks for capabilities in its descriptor ([`PluginDescriptor`]) and the host grants
//!   them only from an explicit operator allow-list ([`CapabilityPolicy`]). Unknown capability
//!   codes are rejected instead of ignored.
//! * **No shared memory and no raw pointers.** Everything crosses the boundary as bytes encoded by
//!   this crate's stable encodings; every decoder is bounds-checked and returns a typed error. A
//!   malformed frame or payload can never panic the host.
//! * **Generation scope.** A plugin instance belongs to one configuration generation; host calls and
//!   configuration snapshots are scoped to it, and calls from a stale instance are rejected after a
//!   reload instead of mixing generations.
//! * **Mandatory limits.** Descriptors must carry positive body/memory/call limits within ABI hard
//!   caps; frames, headers, bodies and host-call arguments are separately bounded.
//!
//! # Versions
//!
//! The ABI is versioned `major.minor` ([`AbiVersion`], [`ABI_VERSION`] = 1.0). Major versions are
//! incompatible; minor versions are additive. The host must be at least as new (minor) as the
//! plugin's target version, and both sides must agree on the major version. Negotiation returns a
//! typed error for every mismatch ([`NegotiationError`]) and never loads a plugin speculatively.
//!
//! # ABI surface
//!
//! * [`descriptor`]: untrusted plugin descriptor, limits and the `validate` + `negotiate` entry
//!   point ([`PluginDescriptor::negotiate`]).
//! * [`capability`]: capability codes, [`CapabilitySet`], operator [`CapabilityPolicy`] and
//!   [`grant_capabilities`].
//! * [`hostcall`]: host-call codes, capability requirements, argument limits, generation-scoped
//!   [`HostCallContext`] authorisation and typed results.
//! * [`bridge`]: request/response heads, streaming body contract, stable frame encodings
//!   ([`BridgeFrame`]) and total-body accounting ([`BodyBudget`]).
//! * [`wasm`] (feature `wasm-runtime`, default on): the in-process Wasmtime host runtime for the
//!   ABI (fuel, wall-clock, memory and body limits, host-function bridging).
//! * [`host`]: host-side lifecycle for external module services (spawn/handshake/host calls,
//!   generation scoping via `caddy-rs-core`'s `GenerationResource`, crash isolation and explicit
//!   supervision with bounded grace/restart policy).
//! * [`protocol`]: the out-of-process/external module protocol (handshake, request multiplexing,
//!   cancellation, deadlines and connection-scoped errors) that reuses the same frame layout and
//!   payload encoders for modules running outside the host process (ADR-0006 item 3, see
//!   `docs/PLUGIN-PROTOCOL.md`).
//! * [`encoding`]: the bounds-checked little-endian reader/writer used by all encodings.
//! * [`error`]: typed errors and the stable [`AbiErrorCode`] values sent to plugins.
//!
//! # Stable wire encodings
//!
//! * Integers are little-endian and fixed width; there is no padding or alignment.
//! * Byte strings and UTF-8 strings are a `u32` little-endian length followed by that many bytes.
//! * A frame is `tag: u8`, `payload_len: u32`, payload; payloads may not exceed
//!   [`bridge::MAX_FRAME_PAYLOAD_BYTES`].
//! * Unknown tags, host-call codes, error codes, methods, body modes and log levels are protocol
//!   errors ([`WireError`]); they are never skipped, because skipping would let a plugin compiled
//!   against a newer minor version run with silently missing behaviour.
//! * The constants in [`bridge`] and [`hostcall`] (`FRAME_*`, `HOST_CALL_*`, capability codes,
//!   [`AbiErrorCode`] values) are part of the ABI and may only be appended/renumbered in a major
//!   version.
//!
//! # Non-goals
//!
//! * No Caddy/Go plugin compatibility: Caddy's compiled-module ecosystem is out of scope.
//! * No WASM runtime, fuel metering, module instantiation or host I/O in this crate (T-PLUG-011).
//! * No manifest file syntax: descriptors are data; the host chooses the serialization format.
//! * No transport implementation: the external module protocol in [`protocol`] is a wire/state
//!   contract; socket/process management, isolation and the HTTP server integration belong to the
//!   host runtime tasks.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod capability;
pub mod descriptor;
pub mod encoding;
pub mod error;
pub mod host;
pub mod hostcall;
pub mod protocol;
pub mod version;
#[cfg(feature = "wasm-runtime")]
pub mod wasm;

pub use bridge::{
    AbiErrorFrame, AbiLimits, BodyBudget, BodyMode, BridgeFrame, BridgeHeaders, BridgeMethod,
    RequestHead, ResponseHead, FRAME_ERROR, FRAME_HOST_CALL, FRAME_HOST_CALL_RESULT,
    FRAME_REQUEST_BODY_CHUNK, FRAME_REQUEST_END, FRAME_REQUEST_HEAD, FRAME_RESPONSE_BODY_CHUNK,
    FRAME_RESPONSE_END, FRAME_RESPONSE_HEAD, MAX_ANNOUNCED_BODY_BYTES, MAX_BODY_CHUNK_BYTES,
    MAX_ERROR_MESSAGE_BYTES, MAX_FRAME_PAYLOAD_BYTES, MAX_HEADER_COUNT, MAX_HEADER_NAME_BYTES,
    MAX_HEADER_VALUE_BYTES, MAX_METHOD_NAME_BYTES, MAX_URI_BYTES,
};
pub use capability::{
    grant_capabilities, Capability, CapabilityPolicy, CapabilitySet, MAX_REQUESTED_CAPABILITIES,
};
pub use descriptor::{
    NegotiatedPlugin, PluginDescriptor, PluginLimits, HARD_MAX_HOST_CALLS_PER_REQUEST,
    HARD_MAX_MEMORY_BYTES, HARD_MAX_REQUEST_BODY_BYTES, HARD_MAX_RESPONSE_BODY_BYTES,
    MAX_PLUGIN_NAME_LEN,
};
pub use encoding::{Reader, Writer};
pub use error::{
    AbiError, AbiErrorCode, CapabilityError, DescriptorError, HostCallError, NegotiationError,
    WireError,
};
pub use host::{
    read_frame, write_frame, DenyAllHostCalls, GenerationModule, GenerationScope, HostCallHandler,
    HostError, HostEvent, HostService, HostServiceConfig, ModuleSupervisor, ModuleTransport,
    ModuleTransportSpec, RestartPolicy, DEFAULT_RESTART_BACKOFF, DEFAULT_STOP_GRACE,
};
pub use hostcall::{
    HostCall, HostCallContext, HostCallResult, LogLevel, HOST_CALL_HTTP_REQUEST, HOST_CALL_LOG,
    HOST_CALL_NOW, HOST_CALL_RANDOM, HOST_CALL_READ_CONFIG, MAX_CONFIG_KEY_BYTES,
    MAX_CONFIG_VALUE_BYTES, MAX_HOST_CALL_BODY_BYTES, MAX_LOG_FIELDS, MAX_LOG_FIELD_NAME_BYTES,
    MAX_LOG_FIELD_VALUE_BYTES, MAX_LOG_MESSAGE_BYTES, MAX_RANDOM_BYTES, MAX_URL_BYTES,
};
pub use protocol::{
    accept_handshake, tighten_limits, validate_handshake_ack, Cancel, ErrorFrame, HandshakeError,
    Hello, HelloAck, HostCallFrame, HostCallResultFrame, HostHandshakeConfig, NegotiatedSession,
    OpenRequest, ProtocolError, ProtocolFrame, Reject, RejectPhase, RequestBodyChunk, RequestEnd,
    RequestId, ResponseBodyChunk, ResponseEnd, ResponseHeadFrame, DEFAULT_BODY_WINDOW_BYTES,
    DEFAULT_MAX_IN_FLIGHT_REQUESTS, FIRST_PROTOCOL_TAG, HOST_PROTOCOL_VERSION, LAST_PROTOCOL_TAG,
    MAX_PROTOCOL_FRAME_PAYLOAD_BYTES, MAX_PROTOCOL_MESSAGE_BYTES, PROTOCOL_VERSION,
    PROTO_FRAME_CANCEL, PROTO_FRAME_ERROR, PROTO_FRAME_HEADER_BYTES, PROTO_FRAME_HELLO,
    PROTO_FRAME_HELLO_ACK, PROTO_FRAME_HOST_CALL, PROTO_FRAME_HOST_CALL_RESULT,
    PROTO_FRAME_OPEN_REQUEST, PROTO_FRAME_REJECT, PROTO_FRAME_REQUEST_BODY_CHUNK,
    PROTO_FRAME_REQUEST_END, PROTO_FRAME_RESPONSE_BODY_CHUNK, PROTO_FRAME_RESPONSE_END,
    PROTO_FRAME_RESPONSE_HEAD,
};
pub use version::{
    decode_abi_version, encode_abi_version, negotiate, AbiVersion, NegotiatedAbi, ABI_MAJOR,
    ABI_MINOR, ABI_VERSION, HOST_ABI_VERSION,
};
#[cfg(feature = "wasm-runtime")]
pub use wasm::{
    DefaultHostCalls, HostCallProvider, WasmError, WasmPlugin, WasmResponse, WasmRuntime,
    WasmRuntimeConfig, DEFAULT_FUEL_PER_REQUEST, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_MODULE_BYTES, DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_REQUEST_TIMEOUT,
};
