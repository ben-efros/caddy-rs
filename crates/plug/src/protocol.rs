//! Out-of-process module protocol (external modules, ADR-0006 item 3).
//!
//! This module defines the wire protocol a caddy-rs module host uses to drive a module that runs
//! in **another process** over a local transport (Unix domain socket or a per-module stdio pair;
//! see `docs/PLUGIN-PROTOCOL.md`). It deliberately reuses the in-process ABI building blocks:
//!
//! * the same frame layout — `tag: u8`, `payload_len: u32` little-endian, payload — and the same
//!   [`Writer`]/[`Reader`] bounds-checked encodings;
//! * the same payload encoders for HTTP heads, headers, body chunks, host calls, host-call results
//!   and ABI error frames ([`crate::bridge::AbiErrorFrame`], [`BridgeHeaders`], [`HostCall`], [`HostCallResult`],
//!   [`RequestHead`], [`ResponseHead`]);
//! * the same [`AbiVersion`] negotiation semantics ([`negotiate`]) for both the transport
//!   (`PROTOCOL_VERSION`) and the plugin ABI (the descriptor's version);
//! * the same capability model and deny-by-default [`CapabilityPolicy`];
//! * the same stable [`AbiErrorCode`] values for abnormal ends.
//!
//! It adds only what an out-of-process transport needs: a handshake, request multiplexing with
//! [`RequestId`]s, deadlines, cancellation and connection-scoped errors. The in-process ABI keeps
//! its frame tags 1..=9; this protocol uses the reserved external range [`FIRST_PROTOCOL_TAG`]..
//! [`LAST_PROTOCOL_TAG`] and rejects in-process tags with a typed error, so the two cannot be
//! confused.
//!
//! Every decoder is bounds-checked and returns [`ProtocolError`] (never panics). Handshake
//! decisions use [`accept_handshake`]/[`validate_handshake_ack`] and report [`HandshakeError`],
//! which can be turned into a [`Reject`] frame for the peer.
//!
//! # Transport
//!
//! One protocol connection carries exactly one module instance: the handshake binds the connection
//! to a validated descriptor and generation, and no later frame may change that binding. The host
//! bounds in-flight requests with the limits it returns in [`HelloAck`]; both sides must apply the
//! backpressure rules documented in `docs/PLUGIN-PROTOCOL.md` and implemented partially here by
//! [`BodyBudget`] and the frame/chunk limits in [`AbiLimits`].

use core::fmt;

use crate::bridge::{
    AbiLimits, BodyBudget, BridgeHeaders, RequestHead, ResponseHead, MAX_BODY_CHUNK_BYTES,
    MAX_ERROR_MESSAGE_BYTES, MAX_FRAME_PAYLOAD_BYTES,
};
use crate::capability::{Capability, CapabilityPolicy, CapabilitySet, MAX_REQUESTED_CAPABILITIES};
use crate::descriptor::{NegotiatedPlugin, PluginDescriptor, PluginLimits, MAX_PLUGIN_NAME_LEN};
use crate::encoding::{Reader, Writer};
use crate::error::{AbiErrorCode, CapabilityError, DescriptorError, NegotiationError, WireError};
use crate::hostcall::{HostCall, HostCallResult};
use crate::version::{negotiate, AbiVersion, NegotiatedAbi, HOST_ABI_VERSION};

/// Version of the external module protocol framing/state machine defined by this module.
///
/// Version negotiation uses the same [`AbiVersion`] rules as the in-process ABI: the major version
/// must match exactly, the host minor must be at least the module's target minor, and a zero major
/// version is invalid. The transport version is negotiated separately from the plugin ABI version
/// carried in the descriptor so each can evolve within its own compatibility rules.
pub const PROTOCOL_VERSION: AbiVersion = AbiVersion::new(1, 0);

/// The protocol version the caddy-rs host advertises.
pub const HOST_PROTOCOL_VERSION: AbiVersion = PROTOCOL_VERSION;

/// First frame tag reserved for the external protocol (in-process ABI uses 1..=9).
pub const FIRST_PROTOCOL_TAG: u8 = 0x10;
/// Last frame tag reserved for the external protocol.
pub const LAST_PROTOCOL_TAG: u8 = 0x2C;

/// Handshake: module to host (requested descriptor, protocol version and capabilities).
pub const PROTO_FRAME_HELLO: u8 = 0x10;
/// Handshake: host to module (negotiated versions, granted capabilities and effective limits).
pub const PROTO_FRAME_HELLO_ACK: u8 = 0x11;
/// Handshake/connection rejection.
pub const PROTO_FRAME_REJECT: u8 = 0x12;

/// Host to module: open a request (request head plus optional deadline).
pub const PROTO_FRAME_OPEN_REQUEST: u8 = 0x20;
/// Host to module: request body chunk.
pub const PROTO_FRAME_REQUEST_BODY_CHUNK: u8 = 0x21;
/// Host to module: end of request body, with optional trailers.
pub const PROTO_FRAME_REQUEST_END: u8 = 0x22;
/// Module to host: response head.
pub const PROTO_FRAME_RESPONSE_HEAD: u8 = 0x23;
/// Module to host: response body chunk.
pub const PROTO_FRAME_RESPONSE_BODY_CHUNK: u8 = 0x24;
/// Module to host: end of response body, with optional trailers.
pub const PROTO_FRAME_RESPONSE_END: u8 = 0x25;
/// Module to host: host call within a request.
pub const PROTO_FRAME_HOST_CALL: u8 = 0x26;
/// Host to module: result of a host call.
pub const PROTO_FRAME_HOST_CALL_RESULT: u8 = 0x27;
/// Either direction: cancel a request.
pub const PROTO_FRAME_CANCEL: u8 = 0x28;
/// Either direction: connection-scoped or request-scoped error.
pub const PROTO_FRAME_ERROR: u8 = 0x29;

/// Default maximum number of concurrently open requests on one connection.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: u16 = 16;

/// Default per-request inbound body window advertised in [`HelloAck`] (1 MiB).
pub const DEFAULT_BODY_WINDOW_BYTES: u32 = 1024 * 1024;

/// Maximum number of bytes a [`Reject`] or [`ErrorFrame`] message may carry.
pub const MAX_PROTOCOL_MESSAGE_BYTES: usize = MAX_ERROR_MESSAGE_BYTES;

/// A non-zero request identifier.
///
/// Request ids are assigned by the host, are unique for the lifetime of a protocol connection and
/// are never reused. Zero is reserved for connection-scoped frames (handshake and connection errors)
/// and is rejected anywhere a request id is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Construct a request id, rejecting the reserved value `0`.
    pub const fn new(id: u64) -> Result<Self, ProtocolError> {
        if id == 0 {
            Err(ProtocolError::ZeroRequestId)
        } else {
            Ok(Self(id))
        }
    }

    /// Raw wire value.
    pub const fn get(self) -> u64 {
        self.0
    }

    fn encode(self, writer: &mut Writer) {
        writer.u64(self.0);
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Self::new(reader.u64()?)
    }
}

/// Handshake frame sent by the module: the protocol version it speaks and its untrusted descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// External protocol version the module targets.
    pub protocol: AbiVersion,
    /// Untrusted module descriptor (name, plugin ABI version, requested capabilities, limits).
    pub descriptor: PluginDescriptor,
}

impl Hello {
    /// Encode the HELLO payload (without frame header).
    pub fn encode(&self, writer: &mut Writer) -> Result<(), ProtocolError> {
        self.protocol.encode(writer);
        writer.string("plugin name", &self.descriptor.name)?;
        self.descriptor.abi.encode(writer);
        if self.descriptor.capabilities.len() > MAX_REQUESTED_CAPABILITIES {
            return Err(ProtocolError::TooManyRequestedCapabilities {
                count: self.descriptor.capabilities.len(),
                max: MAX_REQUESTED_CAPABILITIES,
            });
        }
        writer.u8(
            u8::try_from(self.descriptor.capabilities.len()).map_err(|_| {
                WireError::SizeOverflow {
                    field: "requested capability count",
                }
            })?,
        );
        for code in &self.descriptor.capabilities {
            writer.u32(*code);
        }
        encode_limits(&self.descriptor.limits, writer);
        Ok(())
    }

    /// Decode a HELLO payload and validate the protocol version and descriptor structure.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let protocol = AbiVersion::decode(reader)?;
        let name = reader.string("plugin name", MAX_PLUGIN_NAME_LEN)?;
        let abi = AbiVersion::decode(reader)?;
        let count = reader.u8()? as usize;
        if count > MAX_REQUESTED_CAPABILITIES {
            return Err(ProtocolError::TooManyRequestedCapabilities {
                count,
                max: MAX_REQUESTED_CAPABILITIES,
            });
        }
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(reader.u32()?);
        }
        let limits = decode_limits(reader)?;
        let descriptor = PluginDescriptor {
            name,
            abi,
            capabilities,
            limits,
        };
        // Structural validation is part of decoding: a malformed descriptor is never forwarded to
        // the host's loader.
        descriptor.validate().map_err(ProtocolError::Descriptor)?;
        Ok(Self {
            protocol,
            descriptor,
        })
    }
}

/// Handshake response sent by the host after a successful [`accept_handshake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    /// Effective protocol version both sides use for this connection (the module's target version).
    pub protocol: AbiVersion,
    /// Negotiated plugin ABI versions: the module's target and the host's implementation.
    pub abi: NegotiatedAbi,
    /// Capabilities granted to this module instance (exactly the requested-and-allowed set).
    pub granted: CapabilitySet,
    /// Effective limits: the requested limits tightened by the host.
    pub limits: PluginLimits,
    /// Maximum number of concurrently open requests the module must accept.
    pub max_in_flight_requests: u16,
    /// Per-request inbound body window for backpressure, in bytes.
    pub body_window_bytes: u32,
}

impl HelloAck {
    /// Encode the HELLO_ACK payload (without frame header).
    pub fn encode(&self, writer: &mut Writer) -> Result<(), ProtocolError> {
        self.protocol.encode(writer);
        self.abi.plugin.encode(writer);
        self.abi.host.encode(writer);
        let granted: Vec<Capability> = self.granted.iter().collect();
        writer.u8(
            u8::try_from(granted.len()).map_err(|_| WireError::SizeOverflow {
                field: "granted capability count",
            })?,
        );
        for capability in &granted {
            writer.u32(capability.code());
        }
        encode_limits(&self.limits, writer);
        writer.u16(self.max_in_flight_requests);
        writer.u32(self.body_window_bytes);
        Ok(())
    }

    /// Decode a HELLO_ACK payload, validating versions, capability codes, limits and window bounds.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let protocol = AbiVersion::decode(reader)?;
        let plugin = AbiVersion::decode(reader)?;
        let host = AbiVersion::decode(reader)?;
        let count = reader.u8()? as usize;
        if count > MAX_REQUESTED_CAPABILITIES {
            return Err(ProtocolError::TooManyGrantedCapabilities {
                count,
                max: MAX_REQUESTED_CAPABILITIES,
            });
        }
        let mut granted = CapabilitySet::EMPTY;
        for _ in 0..count {
            let code = reader.u32()?;
            let capability =
                Capability::from_code(code).ok_or(ProtocolError::UnknownCapability { code })?;
            if granted.contains(capability) {
                return Err(ProtocolError::DuplicateCapability { code });
            }
            granted = granted.with(capability);
        }
        let limits = decode_limits(reader)?;
        let max_in_flight_requests = reader.u16()?;
        let body_window_bytes = reader.u32()?;
        if max_in_flight_requests == 0 {
            return Err(ProtocolError::InvalidHelloAck {
                reason: "max_in_flight_requests must be positive",
            });
        }
        if body_window_bytes == 0 {
            return Err(ProtocolError::InvalidHelloAck {
                reason: "body_window_bytes must be positive",
            });
        }
        Ok(Self {
            protocol,
            abi: NegotiatedAbi { plugin, host },
            granted,
            limits,
            max_in_flight_requests,
            body_window_bytes,
        })
    }
}

/// Phase of the handshake a rejection belongs to (diagnostic and audit classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectPhase {
    /// The external protocol version was rejected.
    ProtocolVersion = 1,
    /// The plugin ABI version was rejected.
    AbiVersion = 2,
    /// The descriptor was malformed.
    Descriptor = 3,
    /// A requested capability was not granted (or unknown/duplicated).
    Capability = 4,
    /// Another handshake invariant failed.
    Other = 5,
}

impl RejectPhase {
    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ProtocolVersion),
            2 => Some(Self::AbiVersion),
            3 => Some(Self::Descriptor),
            4 => Some(Self::Capability),
            5 => Some(Self::Other),
            _ => None,
        }
    }
}

/// Connection rejection frame: the host refuses the module (or the module refuses an invalid ACK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    /// Handshake phase that failed.
    pub phase: RejectPhase,
    /// Stable error code the peer can surface/log.
    pub code: AbiErrorCode,
    /// Free-form diagnostic (not part of the stable contract).
    pub message: String,
}

impl Reject {
    /// Encode the REJECT payload (without frame header).
    pub fn encode(&self, writer: &mut Writer) -> Result<(), ProtocolError> {
        writer.u8(self.phase.code());
        writer.u32(self.code.code());
        if self.message.len() > MAX_PROTOCOL_MESSAGE_BYTES {
            return Err(WireError::LimitExceeded {
                field: "reject message",
                len: self.message.len(),
                max: MAX_PROTOCOL_MESSAGE_BYTES,
            }
            .into());
        }
        writer.string("reject message", &self.message)?;
        Ok(())
    }

    /// Decode a REJECT payload.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let phase_code = reader.u8()?;
        let phase = RejectPhase::from_code(phase_code)
            .ok_or(ProtocolError::UnknownRejectPhase { code: phase_code })?;
        let code = reader.u32()?;
        let code =
            AbiErrorCode::from_code(code).ok_or(ProtocolError::UnknownAbiErrorCode { code })?;
        let message = reader.string("reject message", MAX_PROTOCOL_MESSAGE_BYTES)?;
        Ok(Self {
            phase,
            code,
            message,
        })
    }
}

/// Host to module: open a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// Request identifier (unique per connection).
    pub request_id: RequestId,
    /// Remaining time budget for this request in milliseconds; `0` means "no deadline".
    pub deadline_ms: u32,
    /// Bridged request head (method, authority, URI, headers, body mode).
    pub head: RequestHead,
}

/// Host to module: one request body chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBodyChunk {
    /// Request identifier.
    pub request_id: RequestId,
    /// Chunk bytes (at most [`AbiLimits::max_body_chunk`]).
    pub chunk: Vec<u8>,
}

/// Host to module: request body end plus optional trailers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnd {
    /// Request identifier.
    pub request_id: RequestId,
    /// Request trailers (may be empty).
    pub trailers: BridgeHeaders,
}

/// Module to host: response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeadFrame {
    /// Request identifier.
    pub request_id: RequestId,
    /// Bridged response head.
    pub head: ResponseHead,
}

/// Module to host: one response body chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseBodyChunk {
    /// Request identifier.
    pub request_id: RequestId,
    /// Chunk bytes (at most [`AbiLimits::max_body_chunk`]).
    pub chunk: Vec<u8>,
}

/// Module to host: response body end plus optional trailers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseEnd {
    /// Request identifier.
    pub request_id: RequestId,
    /// Response trailers (may be empty).
    pub trailers: BridgeHeaders,
}

/// Module to host: a capability-gated host call made within a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCallFrame {
    /// Request identifier.
    pub request_id: RequestId,
    /// Host call payload (capability validation is the host's job; see [`CapabilitySet`]).
    pub call: HostCall,
}

/// Host to module: the result of a host call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCallResultFrame {
    /// Request identifier.
    pub request_id: RequestId,
    /// Typed host-call result or error.
    pub result: HostCallResult,
}

/// Either direction: cancel a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    /// Request identifier.
    pub request_id: RequestId,
    /// Stable reason code (`Cancelled`, `LimitExceeded`, `PluginFailed`, ...).
    pub code: AbiErrorCode,
    /// Free-form diagnostic.
    pub message: String,
}

/// Either direction: request-scoped (or connection-scoped, when `request_id` is `None`) error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorFrame {
    /// Scope of the error; `None` means the whole connection is being torn down.
    pub request_id: Option<RequestId>,
    /// Whether the connection must be closed after this frame.
    pub fatal: bool,
    /// Stable error code.
    pub code: AbiErrorCode,
    /// Free-form diagnostic.
    pub message: String,
}

impl ErrorFrame {
    /// Build a connection-fatal error frame from a protocol error.
    pub fn from_protocol_error(error: &ProtocolError) -> Self {
        Self {
            request_id: None,
            fatal: true,
            code: error.abi_code(),
            message: error.to_string(),
        }
    }

    /// Build a request-scoped error frame from a protocol error.
    pub fn request_scoped(request_id: RequestId, error: &ProtocolError) -> Self {
        Self {
            request_id: Some(request_id),
            fatal: false,
            code: error.abi_code(),
            message: error.to_string(),
        }
    }

    fn encode(&self, writer: &mut Writer) -> Result<(), ProtocolError> {
        writer.u64(self.request_id.map(RequestId::get).unwrap_or(0));
        writer.u8(u8::from(self.fatal));
        writer.u32(self.code.code());
        if self.message.len() > MAX_PROTOCOL_MESSAGE_BYTES {
            return Err(WireError::LimitExceeded {
                field: "error message",
                len: self.message.len(),
                max: MAX_PROTOCOL_MESSAGE_BYTES,
            }
            .into());
        }
        writer.string("error message", &self.message)?;
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let request_id = reader.u64()?;
        let request_id = if request_id == 0 {
            None
        } else {
            Some(RequestId::new(request_id)?)
        };
        let fatal = match reader.u8()? {
            0 => false,
            1 => true,
            other => {
                return Err(ProtocolError::InvalidErrorFrame {
                    reason: if other > 1 {
                        "fatal flag must be 0 or 1"
                    } else {
                        "invalid fatal flag"
                    },
                })
            }
        };
        let code = reader.u32()?;
        let code =
            AbiErrorCode::from_code(code).ok_or(ProtocolError::UnknownAbiErrorCode { code })?;
        let message = reader.string("error message", MAX_PROTOCOL_MESSAGE_BYTES)?;
        Ok(Self {
            request_id,
            fatal,
            code,
            message,
        })
    }
}

/// One frame of the external module protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolFrame {
    /// Module to host handshake request.
    Hello(Hello),
    /// Host to module handshake response.
    HelloAck(HelloAck),
    /// Handshake/connection rejection.
    Reject(Reject),
    /// Host to module request open.
    OpenRequest(OpenRequest),
    /// Host to module request body chunk.
    RequestBodyChunk(RequestBodyChunk),
    /// Host to module request end.
    RequestEnd(RequestEnd),
    /// Module to host response head.
    ResponseHead(ResponseHeadFrame),
    /// Module to host response body chunk.
    ResponseBodyChunk(ResponseBodyChunk),
    /// Module to host response end.
    ResponseEnd(ResponseEnd),
    /// Module to host host call.
    HostCall(HostCallFrame),
    /// Host to module host-call result.
    HostCallResult(HostCallResultFrame),
    /// Either direction request cancellation.
    Cancel(Cancel),
    /// Either direction error.
    Error(ErrorFrame),
}

impl ProtocolFrame {
    /// Stable frame tag.
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Hello(_) => PROTO_FRAME_HELLO,
            Self::HelloAck(_) => PROTO_FRAME_HELLO_ACK,
            Self::Reject(_) => PROTO_FRAME_REJECT,
            Self::OpenRequest(_) => PROTO_FRAME_OPEN_REQUEST,
            Self::RequestBodyChunk(_) => PROTO_FRAME_REQUEST_BODY_CHUNK,
            Self::RequestEnd(_) => PROTO_FRAME_REQUEST_END,
            Self::ResponseHead(_) => PROTO_FRAME_RESPONSE_HEAD,
            Self::ResponseBodyChunk(_) => PROTO_FRAME_RESPONSE_BODY_CHUNK,
            Self::ResponseEnd(_) => PROTO_FRAME_RESPONSE_END,
            Self::HostCall(_) => PROTO_FRAME_HOST_CALL,
            Self::HostCallResult(_) => PROTO_FRAME_HOST_CALL_RESULT,
            Self::Cancel(_) => PROTO_FRAME_CANCEL,
            Self::Error(_) => PROTO_FRAME_ERROR,
        }
    }

    /// Whether this is a handshake frame (HELLO/HELLO_ACK/REJECT).
    pub const fn is_handshake(&self) -> bool {
        matches!(self, Self::Hello(_) | Self::HelloAck(_) | Self::Reject(_))
    }

    /// Encode a complete frame (`tag: u8`, `payload_len: u32`, payload).
    ///
    /// The payload limit is [`AbiLimits::max_frame_payload`]; `limits` must be the effective limits
    /// negotiated for this connection (which are never above the ABI defaults).
    pub fn encode(&self, limits: &AbiLimits) -> Result<Vec<u8>, ProtocolError> {
        let mut payload = Writer::new();
        match self {
            Self::Hello(hello) => hello.encode(&mut payload)?,
            Self::HelloAck(ack) => ack.encode(&mut payload)?,
            Self::Reject(reject) => reject.encode(&mut payload)?,
            Self::OpenRequest(frame) => {
                frame.request_id.encode(&mut payload);
                payload.u32(frame.deadline_ms);
                frame.head.encode(&mut payload, limits)?;
            }
            Self::RequestBodyChunk(frame) => {
                frame.request_id.encode(&mut payload);
                encode_chunk(&frame.chunk, limits, &mut payload)?;
            }
            Self::RequestEnd(frame) => {
                frame.request_id.encode(&mut payload);
                frame.trailers.encode(&mut payload, limits)?;
            }
            Self::ResponseHead(frame) => {
                frame.request_id.encode(&mut payload);
                frame.head.encode(&mut payload, limits)?;
            }
            Self::ResponseBodyChunk(frame) => {
                frame.request_id.encode(&mut payload);
                encode_chunk(&frame.chunk, limits, &mut payload)?;
            }
            Self::ResponseEnd(frame) => {
                frame.request_id.encode(&mut payload);
                frame.trailers.encode(&mut payload, limits)?;
            }
            Self::HostCall(frame) => {
                frame.request_id.encode(&mut payload);
                frame.call.encode(&mut payload, limits)?;
            }
            Self::HostCallResult(frame) => {
                frame.request_id.encode(&mut payload);
                frame.result.encode(&mut payload, limits)?;
            }
            Self::Cancel(frame) => {
                frame.request_id.encode(&mut payload);
                payload.u32(frame.code.code());
                if frame.message.len() > MAX_PROTOCOL_MESSAGE_BYTES {
                    return Err(WireError::LimitExceeded {
                        field: "cancel message",
                        len: frame.message.len(),
                        max: MAX_PROTOCOL_MESSAGE_BYTES,
                    }
                    .into());
                }
                payload.string("cancel message", &frame.message)?;
            }
            Self::Error(frame) => frame.encode(&mut payload)?,
        }
        let payload = payload.into_vec();
        if payload.len() > limits.max_frame_payload {
            return Err(WireError::FrameTooLarge {
                len: payload.len(),
                max: limits.max_frame_payload,
            }
            .into());
        }
        let mut frame = Writer::with_capacity(5 + payload.len());
        frame.u8(self.tag());
        frame.u32(
            u32::try_from(payload.len()).map_err(|_| WireError::SizeOverflow {
                field: "frame payload",
            })?,
        );
        let mut bytes = frame.into_vec();
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decode one frame from the start of `bytes`, returning it and the number of bytes consumed.
    ///
    /// Trailing bytes belong to the next frame (stream decoding) and are not an error; callers must
    /// advance by the returned count. Validation is complete for the frame itself: unknown tags,
    /// in-process ABI tags, oversized payloads, malformed payloads and zero request ids are typed
    /// errors.
    pub fn decode(bytes: &[u8], limits: &AbiLimits) -> Result<(Self, usize), ProtocolError> {
        if bytes.is_empty() {
            return Err(WireError::EmptyFrame.into());
        }
        let mut reader = Reader::new(bytes);
        let tag = reader.u8()?;
        let payload_len = reader.u32()? as usize;
        if payload_len > limits.max_frame_payload {
            return Err(WireError::FrameTooLarge {
                len: payload_len,
                max: limits.max_frame_payload,
            }
            .into());
        }
        let payload = reader.take(payload_len)?;
        let consumed = 5 + payload_len;
        let mut payload = Reader::new(payload);
        let frame = match tag {
            PROTO_FRAME_HELLO => Self::Hello(Hello::decode(&mut payload)?),
            PROTO_FRAME_HELLO_ACK => Self::HelloAck(HelloAck::decode(&mut payload)?),
            PROTO_FRAME_REJECT => Self::Reject(Reject::decode(&mut payload)?),
            PROTO_FRAME_OPEN_REQUEST => {
                let request_id = RequestId::decode(&mut payload)?;
                let deadline_ms = payload.u32()?;
                let head = RequestHead::decode(&mut payload, limits)?;
                Self::OpenRequest(OpenRequest {
                    request_id,
                    deadline_ms,
                    head,
                })
            }
            PROTO_FRAME_REQUEST_BODY_CHUNK => {
                let request_id = RequestId::decode(&mut payload)?;
                let chunk = decode_chunk(&mut payload, limits)?;
                Self::RequestBodyChunk(RequestBodyChunk { request_id, chunk })
            }
            PROTO_FRAME_REQUEST_END => {
                let request_id = RequestId::decode(&mut payload)?;
                let trailers = BridgeHeaders::decode(&mut payload, limits)?;
                Self::RequestEnd(RequestEnd {
                    request_id,
                    trailers,
                })
            }
            PROTO_FRAME_RESPONSE_HEAD => {
                let request_id = RequestId::decode(&mut payload)?;
                let head = ResponseHead::decode(&mut payload, limits)?;
                Self::ResponseHead(ResponseHeadFrame { request_id, head })
            }
            PROTO_FRAME_RESPONSE_BODY_CHUNK => {
                let request_id = RequestId::decode(&mut payload)?;
                let chunk = decode_chunk(&mut payload, limits)?;
                Self::ResponseBodyChunk(ResponseBodyChunk { request_id, chunk })
            }
            PROTO_FRAME_RESPONSE_END => {
                let request_id = RequestId::decode(&mut payload)?;
                let trailers = BridgeHeaders::decode(&mut payload, limits)?;
                Self::ResponseEnd(ResponseEnd {
                    request_id,
                    trailers,
                })
            }
            PROTO_FRAME_HOST_CALL => {
                let request_id = RequestId::decode(&mut payload)?;
                let call = HostCall::decode(&mut payload, limits)?;
                Self::HostCall(HostCallFrame { request_id, call })
            }
            PROTO_FRAME_HOST_CALL_RESULT => {
                let request_id = RequestId::decode(&mut payload)?;
                let result = HostCallResult::decode(&mut payload, limits)?;
                Self::HostCallResult(HostCallResultFrame { request_id, result })
            }
            PROTO_FRAME_CANCEL => {
                let request_id = RequestId::decode(&mut payload)?;
                let code = payload.u32()?;
                let code = AbiErrorCode::from_code(code)
                    .ok_or(ProtocolError::UnknownAbiErrorCode { code })?;
                let message = payload.string("cancel message", MAX_PROTOCOL_MESSAGE_BYTES)?;
                Self::Cancel(Cancel {
                    request_id,
                    code,
                    message,
                })
            }
            PROTO_FRAME_ERROR => Self::Error(ErrorFrame::decode(&mut payload)?),
            other => {
                if (1..=9).contains(&other) {
                    return Err(ProtocolError::InProcessFrameTag { tag: other });
                }
                return Err(WireError::UnknownFrameTag { tag: other }.into());
            }
        };
        payload.finish()?;
        Ok((frame, consumed))
    }
}

fn encode_limits(limits: &PluginLimits, writer: &mut Writer) {
    writer.u64(limits.max_request_body_bytes);
    writer.u64(limits.max_response_body_bytes);
    writer.u32(limits.max_host_calls_per_request);
    writer.u64(limits.max_memory_bytes);
}

fn decode_limits(reader: &mut Reader<'_>) -> Result<PluginLimits, ProtocolError> {
    let limits = PluginLimits {
        max_request_body_bytes: reader.u64()?,
        max_response_body_bytes: reader.u64()?,
        max_host_calls_per_request: reader.u32()?,
        max_memory_bytes: reader.u64()?,
    };
    limits.validate().map_err(ProtocolError::Descriptor)?;
    Ok(limits)
}

fn encode_chunk(
    chunk: &[u8],
    limits: &AbiLimits,
    writer: &mut Writer,
) -> Result<(), ProtocolError> {
    if chunk.len() > limits.max_body_chunk {
        return Err(WireError::LimitExceeded {
            field: "body chunk",
            len: chunk.len(),
            max: limits.max_body_chunk,
        }
        .into());
    }
    writer.bytes("body chunk", chunk)?;
    Ok(())
}

fn decode_chunk(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Vec<u8>, ProtocolError> {
    Ok(reader.bytes("body chunk", limits.max_body_chunk)?.to_vec())
}

/// Configuration the host uses to accept a module handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHandshakeConfig {
    /// External protocol version this host implements.
    pub host_protocol: AbiVersion,
    /// Plugin ABI version this host implements.
    pub host_abi: AbiVersion,
    /// Operator capability allow-list (deny-all by default).
    pub policy: CapabilityPolicy,
    /// Host-side upper bounds; the effective limits are the element-wise minimum with the module's
    /// requested limits.
    pub host_limits: PluginLimits,
    /// Maximum concurrently open requests advertised to the module (must be positive).
    pub max_in_flight_requests: u16,
    /// Per-request inbound body window advertised to the module (must be positive).
    pub body_window_bytes: u32,
}

impl Default for HostHandshakeConfig {
    fn default() -> Self {
        Self {
            host_protocol: HOST_PROTOCOL_VERSION,
            host_abi: HOST_ABI_VERSION,
            policy: CapabilityPolicy::deny_all(),
            host_limits: PluginLimits::default_limits(),
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            body_window_bytes: DEFAULT_BODY_WINDOW_BYTES,
        }
    }
}

impl HostHandshakeConfig {
    fn validate(&self) -> Result<(), HandshakeError> {
        if self.max_in_flight_requests == 0 {
            return Err(HandshakeError::InvalidConfig {
                reason: "max_in_flight_requests must be positive",
            });
        }
        if self.body_window_bytes == 0 {
            return Err(HandshakeError::InvalidConfig {
                reason: "body_window_bytes must be positive",
            });
        }
        self.host_limits
            .validate()
            .map_err(HandshakeError::Descriptor)?;
        Ok(())
    }
}

/// Handshake failure, classified for [`Reject`] frames and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// External protocol version negotiation failed.
    ProtocolVersion(NegotiationError),
    /// Plugin ABI version negotiation failed.
    AbiVersion(NegotiationError),
    /// The descriptor is malformed or its limits exceed the ABI caps.
    Descriptor(DescriptorError),
    /// Requested capabilities were unknown, duplicated or not granted by the policy.
    Capability(CapabilityError),
    /// The host configuration is invalid (programming error on the host side).
    InvalidConfig {
        /// What is invalid.
        reason: &'static str,
    },
    /// The module rejected/validated an ACK that violates the handshake contract.
    InvalidAck {
        /// What is invalid in the ACK.
        reason: &'static str,
    },
}

impl HandshakeError {
    /// Handshake phase this error belongs to.
    pub const fn phase(&self) -> RejectPhase {
        match self {
            Self::ProtocolVersion(_) => RejectPhase::ProtocolVersion,
            Self::AbiVersion(_) => RejectPhase::AbiVersion,
            Self::Descriptor(_) => RejectPhase::Descriptor,
            Self::Capability(_) => RejectPhase::Capability,
            Self::InvalidConfig { .. } | Self::InvalidAck { .. } => RejectPhase::Other,
        }
    }

    /// Stable ABI error code the peer receives.
    pub const fn abi_code(&self) -> AbiErrorCode {
        match self {
            Self::ProtocolVersion(_) | Self::AbiVersion(_) => AbiErrorCode::Unsupported,
            Self::Descriptor(_) => AbiErrorCode::InvalidRequest,
            Self::Capability(_) => AbiErrorCode::CapabilityDenied,
            Self::InvalidConfig { .. } => AbiErrorCode::HostFailure,
            Self::InvalidAck { .. } => AbiErrorCode::InvalidRequest,
        }
    }

    /// Materialise this failure as a [`Reject`] frame.
    pub fn to_reject(&self) -> Reject {
        Reject {
            phase: self.phase(),
            code: self.abi_code(),
            message: self.to_string(),
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersion(error) => {
                write!(formatter, "external protocol version rejected: {error}")
            }
            Self::AbiVersion(error) => write!(formatter, "plugin ABI version rejected: {error}"),
            Self::Descriptor(error) => write!(formatter, "plugin descriptor rejected: {error}"),
            Self::Capability(error) => write!(formatter, "capability grant rejected: {error}"),
            Self::InvalidConfig { reason } => {
                write!(formatter, "invalid host handshake configuration: {reason}")
            }
            Self::InvalidAck { reason } => {
                write!(formatter, "invalid handshake acknowledgement: {reason}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<NegotiationError> for HandshakeError {
    fn from(error: NegotiationError) -> Self {
        Self::ProtocolVersion(error)
    }
}

/// Host side of the handshake: validate a [`Hello`] and produce the [`HelloAck`] to send.
///
/// Steps, in order (each failure is a distinct [`HandshakeError`]):
///
/// 1. negotiate the external protocol version ([`negotiate`], same rules as the ABI version);
/// 2. validate the untrusted descriptor structure;
/// 3. negotiate the plugin ABI version and grant capabilities through the operator policy
///    ([`PluginDescriptor::negotiate`]);
/// 4. tighten the requested limits to the host's limits;
/// 5. return the ACK with the effective versions, granted set, limits and window bounds.
pub fn accept_handshake(
    hello: &Hello,
    config: &HostHandshakeConfig,
) -> Result<HelloAck, HandshakeError> {
    config.validate()?;
    let protocol =
        negotiate(config.host_protocol, hello.protocol).map_err(HandshakeError::ProtocolVersion)?;
    let negotiated: NegotiatedPlugin = hello
        .descriptor
        .negotiate(config.host_abi, &config.policy)
        .map_err(|error| match error {
            crate::error::AbiError::Negotiation(error) => HandshakeError::AbiVersion(error),
            crate::error::AbiError::Capability(error) => HandshakeError::Capability(error),
            crate::error::AbiError::Descriptor(error) => HandshakeError::Descriptor(error),
            // `PluginDescriptor::negotiate` only performs the three steps above.
            other => HandshakeError::InvalidConfig {
                reason: match other {
                    crate::error::AbiError::HostCall(_) => "unexpected host-call error",
                    crate::error::AbiError::Wire(_) => "unexpected wire error",
                    _ => "unexpected negotiation error",
                },
            },
        })?;
    Ok(HelloAck {
        // The effective transport version is the module's target: the host may be newer, but the
        // module compiled against exactly this version.
        protocol: protocol.effective(),
        abi: negotiated.abi,
        granted: negotiated.granted,
        limits: tighten_limits(&negotiated.limits, &config.host_limits),
        max_in_flight_requests: config.max_in_flight_requests,
        body_window_bytes: config.body_window_bytes,
    })
}

/// Result of a validated handshake, as seen by the module side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    /// Effective external protocol version.
    pub protocol: AbiVersion,
    /// Negotiated plugin ABI versions.
    pub abi: NegotiatedAbi,
    /// Capabilities granted to this connection (subset of the requested set).
    pub granted: CapabilitySet,
    /// Effective limits (never larger than the module requested).
    pub limits: PluginLimits,
    /// Maximum concurrent requests the module must accept.
    pub max_in_flight_requests: u16,
    /// Per-request inbound body window.
    pub body_window_bytes: u32,
}

/// Module side of the handshake: validate the host's [`HelloAck`] against the [`Hello`] sent.
///
/// This rejects ACKs that would silently weaken or escalate the session: a different protocol
/// version than the module targeted, an incompatible plugin ABI, grants outside the requested set,
/// limits larger than the module asked for, or zero window bounds.
pub fn validate_handshake_ack(
    hello: &Hello,
    ack: &HelloAck,
) -> Result<NegotiatedSession, HandshakeError> {
    if ack.protocol != hello.protocol {
        return Err(HandshakeError::InvalidAck {
            reason: "ack protocol version differs from the version the module requested",
        });
    }
    if ack.abi.plugin != hello.descriptor.abi {
        return Err(HandshakeError::InvalidAck {
            reason: "ack plugin ABI version differs from the descriptor",
        });
    }
    if ack.abi.host.major != ack.abi.plugin.major || ack.abi.host.minor < ack.abi.plugin.minor {
        return Err(HandshakeError::InvalidAck {
            reason: "ack host ABI version is not compatible with the plugin ABI version",
        });
    }
    let requested: Vec<u32> = hello.descriptor.capabilities.clone();
    for capability in ack.granted.iter() {
        let code = capability.code();
        if !requested.contains(&code) {
            return Err(HandshakeError::InvalidAck {
                reason: "ack granted a capability that was not requested",
            });
        }
    }
    let requested_limits = hello.descriptor.limits;
    for (field, granted, requested) in [
        (
            "max_request_body_bytes",
            ack.limits.max_request_body_bytes,
            requested_limits.max_request_body_bytes,
        ),
        (
            "max_response_body_bytes",
            ack.limits.max_response_body_bytes,
            requested_limits.max_response_body_bytes,
        ),
        (
            "max_memory_bytes",
            ack.limits.max_memory_bytes,
            requested_limits.max_memory_bytes,
        ),
    ] {
        if granted > requested {
            return Err(HandshakeError::InvalidAck {
                reason: if field == "max_request_body_bytes" {
                    "ack request-body limit exceeds the requested limit"
                } else if field == "max_response_body_bytes" {
                    "ack response-body limit exceeds the requested limit"
                } else {
                    "ack memory limit exceeds the requested limit"
                },
            });
        }
    }
    if ack.limits.max_host_calls_per_request > requested_limits.max_host_calls_per_request {
        return Err(HandshakeError::InvalidAck {
            reason: "ack host-call budget exceeds the requested limit",
        });
    }
    ack.limits.validate().map_err(HandshakeError::Descriptor)?;
    if ack.max_in_flight_requests == 0 {
        return Err(HandshakeError::InvalidAck {
            reason: "ack max_in_flight_requests is zero",
        });
    }
    if ack.body_window_bytes == 0 {
        return Err(HandshakeError::InvalidAck {
            reason: "ack body_window_bytes is zero",
        });
    }
    Ok(NegotiatedSession {
        protocol: ack.protocol,
        abi: ack.abi,
        granted: ack.granted,
        limits: ack.limits,
        max_in_flight_requests: ack.max_in_flight_requests,
        body_window_bytes: ack.body_window_bytes,
    })
}

/// Element-wise minimum of two limit sets, used by [`accept_handshake`] to tighten requested limits.
pub fn tighten_limits(requested: &PluginLimits, host: &PluginLimits) -> PluginLimits {
    PluginLimits {
        max_request_body_bytes: requested
            .max_request_body_bytes
            .min(host.max_request_body_bytes),
        max_response_body_bytes: requested
            .max_response_body_bytes
            .min(host.max_response_body_bytes),
        max_host_calls_per_request: requested
            .max_host_calls_per_request
            .min(host.max_host_calls_per_request),
        max_memory_bytes: requested.max_memory_bytes.min(host.max_memory_bytes),
    }
}

/// Error type for the external protocol: framing, handshake and state-machine failures.
///
/// Every variant maps to a stable [`AbiErrorCode`] via [`ProtocolError::abi_code`], so a host can
/// fail a request or the connection with the same coarse code the in-process ABI uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The peer sent a malformed frame or payload.
    Wire(WireError),
    /// The peer requested a handshake feature/version this side does not implement.
    Handshake(HandshakeError),
    /// A frame tag is outside the external protocol range.
    UnknownFrameTag {
        /// Offending tag byte.
        tag: u8,
    },
    /// The peer used an in-process ABI frame tag on the external transport.
    InProcessFrameTag {
        /// Offending in-process tag.
        tag: u8,
    },
    /// A request-scoped frame used the reserved request id `0`.
    ZeroRequestId,
    /// The peer requested more capabilities than a descriptor may contain.
    TooManyRequestedCapabilities {
        /// Requested count.
        count: usize,
        /// Maximum accepted.
        max: usize,
    },
    /// The peer granted more capabilities than a descriptor may contain.
    TooManyGrantedCapabilities {
        /// Granted count.
        count: usize,
        /// Maximum accepted.
        max: usize,
    },
    /// The peer named a capability code this protocol version does not define.
    UnknownCapability {
        /// Offending code.
        code: u32,
    },
    /// The peer named the same capability code twice.
    DuplicateCapability {
        /// Offending code.
        code: u32,
    },
    /// The peer named an undefined rejection phase.
    UnknownRejectPhase {
        /// Offending phase byte.
        code: u8,
    },
    /// The peer named an undefined ABI error code.
    UnknownAbiErrorCode {
        /// Offending code.
        code: u32,
    },
    /// A framed ACK violates the handshake contract.
    InvalidHelloAck {
        /// What is invalid.
        reason: &'static str,
    },
    /// An error frame has an invalid flag value.
    InvalidErrorFrame {
        /// What is invalid.
        reason: &'static str,
    },
    /// The descriptor in the handshake is invalid.
    Descriptor(DescriptorError),
}

impl ProtocolError {
    /// Stable ABI error code for this failure.
    pub const fn abi_code(&self) -> AbiErrorCode {
        match self {
            Self::Wire(_) | Self::InProcessFrameTag { .. } | Self::ZeroRequestId => {
                AbiErrorCode::InvalidRequest
            }
            Self::Handshake(error) => error.abi_code(),
            Self::UnknownFrameTag { .. }
            | Self::UnknownCapability { .. }
            | Self::UnknownRejectPhase { .. }
            | Self::UnknownAbiErrorCode { .. } => AbiErrorCode::Unsupported,
            Self::TooManyRequestedCapabilities { .. }
            | Self::TooManyGrantedCapabilities { .. }
            | Self::DuplicateCapability { .. } => AbiErrorCode::LimitExceeded,
            Self::InvalidHelloAck { .. } | Self::InvalidErrorFrame { .. } => {
                AbiErrorCode::InvalidRequest
            }
            Self::Descriptor(_) => AbiErrorCode::InvalidRequest,
        }
    }

    /// Materialise this failure as a request-scoped or connection-scoped [`ErrorFrame`].
    pub fn to_error_frame(&self, request_id: Option<RequestId>) -> ErrorFrame {
        ErrorFrame {
            request_id,
            fatal: request_id.is_none(),
            code: self.abi_code(),
            message: self.to_string(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "protocol wire error: {error}"),
            Self::Handshake(error) => write!(formatter, "protocol handshake error: {error}"),
            Self::UnknownFrameTag { tag } => {
                write!(formatter, "unknown external protocol frame tag {tag:#04x}")
            }
            Self::InProcessFrameTag { tag } => write!(
                formatter,
                "in-process ABI frame tag {tag} is not valid on the external module protocol"
            ),
            Self::ZeroRequestId => write!(
                formatter,
                "request id 0 is reserved for connection-scoped frames"
            ),
            Self::TooManyRequestedCapabilities { count, max } => write!(
                formatter,
                "{count} requested capabilities exceed the maximum of {max}"
            ),
            Self::TooManyGrantedCapabilities { count, max } => write!(
                formatter,
                "{count} granted capabilities exceed the maximum of {max}"
            ),
            Self::UnknownCapability { code } => write!(
                formatter,
                "unknown capability code {code}: this protocol version defines capabilities 1..=5"
            ),
            Self::DuplicateCapability { code } => {
                write!(formatter, "capability code {code} appears more than once")
            }
            Self::UnknownRejectPhase { code } => {
                write!(formatter, "unknown reject phase byte {code}")
            }
            Self::UnknownAbiErrorCode { code } => {
                write!(formatter, "unknown ABI error code {code}")
            }
            Self::InvalidHelloAck { reason } => {
                write!(formatter, "invalid handshake acknowledgement: {reason}")
            }
            Self::InvalidErrorFrame { reason } => {
                write!(formatter, "invalid error frame: {reason}")
            }
            Self::Descriptor(error) => write!(formatter, "invalid descriptor: {error}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<WireError> for ProtocolError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<HandshakeError> for ProtocolError {
    fn from(error: HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

/// Fixed overhead of a frame with an empty payload: `tag` + `payload_len`.
pub const PROTO_FRAME_HEADER_BYTES: usize = 5;

/// Maximum payload bytes a frame may carry (re-exported for protocol implementers).
pub const MAX_PROTOCOL_FRAME_PAYLOAD_BYTES: usize = MAX_FRAME_PAYLOAD_BYTES;

/// Maximum body chunk bytes carried by a chunk frame (re-exported for protocol implementers).
pub const MAX_PROTOCOL_BODY_CHUNK_BYTES: usize = MAX_BODY_CHUNK_BYTES;

/// Accounting helper for the protocol backpressure rule: a module must not receive more than the
/// negotiated per-request body window before it has produced/consumed frames.
///
/// The host charges every request body chunk against a fresh budget per request
/// ([`BodyBudget::new`] with the request's effective request-body limit) and additionally keeps a
/// window of unacknowledged bytes; this alias documents that the protocol reuses the in-process
/// body-accounting type rather than inventing a second one.
pub type ProtocolBodyBudget = BodyBudget;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{BodyMode, BridgeMethod};
    use crate::descriptor::PluginDescriptor;

    fn descriptor(capabilities: Vec<u32>) -> PluginDescriptor {
        PluginDescriptor {
            name: "echo".to_string(),
            abi: AbiVersion::ABI_1_0,
            capabilities,
            limits: PluginLimits::default_limits(),
        }
    }

    fn make_hello(capabilities: Vec<u32>) -> Hello {
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
            path_and_query: "/hello?name=world".to_string(),
            headers: BridgeHeaders::new([("X-Test".to_string(), "1".to_string())])
                .expect("headers"),
            body: BodyMode::Streamed,
        }
    }

    fn response_head() -> ResponseHead {
        ResponseHead {
            status: 200,
            headers: BridgeHeaders::new([("Content-Type".to_string(), "text/plain".to_string())])
                .expect("headers"),
            body: BodyMode::Streamed,
        }
    }

    #[test]
    fn handshake_accepts_and_grants_requested_capabilities() {
        let hello = make_hello(vec![Capability::Log.code()]);
        let config = HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([Capability::Log]),
            ..HostHandshakeConfig::default()
        };
        let ack = accept_handshake(&hello, &config).expect("handshake accepted");
        assert_eq!(ack.protocol, PROTOCOL_VERSION);
        assert_eq!(ack.abi.plugin, AbiVersion::ABI_1_0);
        assert_eq!(ack.abi.host, HOST_ABI_VERSION);
        assert!(ack.granted.contains(Capability::Log));
        assert_eq!(ack.granted.iter().count(), 1);
        assert_eq!(
            ack.limits.max_request_body_bytes,
            hello.descriptor.limits.max_request_body_bytes
        );
        let session = validate_handshake_ack(&hello, &ack).expect("module accepts ack");
        assert_eq!(session.granted, ack.granted);
    }

    #[test]
    fn handshake_rejects_ungranted_capability() {
        let hello = make_hello(vec![Capability::Random.code()]);
        let config = HostHandshakeConfig::default(); // deny all
        let error = accept_handshake(&hello, &config).expect_err("deny-all rejects");
        assert_eq!(
            error,
            HandshakeError::Capability(CapabilityError::NotGranted {
                capability: Capability::Random
            })
        );
        assert_eq!(error.abi_code(), AbiErrorCode::CapabilityDenied);
        let reject = error.to_reject();
        assert_eq!(reject.phase, RejectPhase::Capability);
    }

    #[test]
    fn handshake_rejects_version_mismatch_in_both_axes() {
        let mut hello = make_hello(Vec::new());
        hello.protocol = AbiVersion::new(2, 0);
        let error = accept_handshake(&hello, &HostHandshakeConfig::default())
            .expect_err("protocol major mismatch");
        assert_eq!(error.phase(), RejectPhase::ProtocolVersion);

        let mut hello = make_hello(Vec::new());
        hello.descriptor.abi = AbiVersion::new(1, 9);
        let error = accept_handshake(&hello, &HostHandshakeConfig::default())
            .expect_err("abi minor too new");
        assert_eq!(error.phase(), RejectPhase::AbiVersion);
        assert_eq!(error.abi_code(), AbiErrorCode::Unsupported);
    }

    #[test]
    fn handshake_rejects_unknown_and_duplicate_capabilities() {
        let error = accept_handshake(
            &make_hello(vec![99]),
            &HostHandshakeConfig {
                policy: CapabilityPolicy::grant_all_v1(),
                ..HostHandshakeConfig::default()
            },
        )
        .expect_err("unknown capability");
        assert_eq!(
            error,
            HandshakeError::Capability(CapabilityError::Unsupported { code: 99 })
        );

        let duplicate = make_hello(vec![Capability::Log.code(), Capability::Log.code()]);
        let error = accept_handshake(
            &duplicate,
            &HostHandshakeConfig {
                policy: CapabilityPolicy::grant_all_v1(),
                ..HostHandshakeConfig::default()
            },
        )
        .expect_err("duplicate capability");
        assert_eq!(
            error,
            HandshakeError::Capability(CapabilityError::Duplicate {
                code: Capability::Log.code()
            })
        );
    }

    #[test]
    fn module_rejects_invalid_ack() {
        let hello = make_hello(vec![Capability::Log.code()]);
        let mut ack = HelloAck {
            protocol: PROTOCOL_VERSION,
            abi: NegotiatedAbi {
                plugin: AbiVersion::ABI_1_0,
                host: HOST_ABI_VERSION,
            },
            granted: CapabilitySet::from_capabilities([Capability::Log]),
            limits: hello.descriptor.limits,
            max_in_flight_requests: 1,
            body_window_bytes: 1,
        };
        assert!(validate_handshake_ack(&hello, &ack).is_ok());
        ack.granted = CapabilitySet::from_capabilities([Capability::Random]);
        let error = validate_handshake_ack(&hello, &ack).expect_err("unrequested grant");
        assert_eq!(
            error,
            HandshakeError::InvalidAck {
                reason: "ack granted a capability that was not requested"
            }
        );
        ack.granted = CapabilitySet::from_capabilities([Capability::Log]);
        ack.limits.max_request_body_bytes += 1;
        let error = validate_handshake_ack(&hello, &ack).expect_err("limit escalation");
        assert_eq!(error.phase(), RejectPhase::Other);
    }

    #[test]
    fn hello_and_ack_round_trip_and_reject_bad_versions() {
        let hello = make_hello(vec![Capability::Log.code(), Capability::Clock.code()]);
        let mut payload = Writer::new();
        hello.encode(&mut payload).expect("encode hello");
        let payload = payload.into_vec();
        let mut reader = Reader::new(&payload);
        assert_eq!(Hello::decode(&mut reader).expect("decode hello"), hello);
        reader.finish().expect("consumed");

        let ack = HelloAck {
            protocol: PROTOCOL_VERSION,
            abi: NegotiatedAbi {
                plugin: AbiVersion::ABI_1_0,
                host: HOST_ABI_VERSION,
            },
            granted: CapabilitySet::from_capabilities([Capability::Log]),
            limits: PluginLimits::default_limits(),
            max_in_flight_requests: 4,
            body_window_bytes: 4096,
        };
        let mut payload = Writer::new();
        ack.encode(&mut payload).expect("encode ack");
        let payload = payload.into_vec();
        let mut reader = Reader::new(&payload);
        assert_eq!(HelloAck::decode(&mut reader).expect("decode ack"), ack);
        reader.finish().expect("consumed");

        // A zero major protocol version on the wire is a typed error, not a panic.
        let mut writer = Writer::new();
        AbiVersion::new(0, 0).encode(&mut writer);
        writer.string("plugin name", "echo").expect("name");
        AbiVersion::ABI_1_0.encode(&mut writer);
        writer.u8(0);
        encode_limits(&PluginLimits::default_limits(), &mut writer);
        let bytes = writer.into_vec();
        let mut reader = Reader::new(&bytes);
        assert!(matches!(
            Hello::decode(&mut reader),
            Err(ProtocolError::Wire(WireError::InvalidAbiVersion { .. }))
        ));
    }

    #[test]
    fn every_variant_round_trips_through_frames() {
        let limits = AbiLimits::spec_defaults();
        let request_id = RequestId::new(7).expect("id");
        let frames = vec![
            ProtocolFrame::Hello(make_hello(vec![Capability::Log.code()])),
            ProtocolFrame::HelloAck(HelloAck {
                protocol: PROTOCOL_VERSION,
                abi: NegotiatedAbi {
                    plugin: AbiVersion::ABI_1_0,
                    host: HOST_ABI_VERSION,
                },
                granted: CapabilitySet::from_capabilities([Capability::Log]),
                limits: PluginLimits::default_limits(),
                max_in_flight_requests: 2,
                body_window_bytes: 1024,
            }),
            ProtocolFrame::Reject(HandshakeError::InvalidConfig { reason: "test" }.to_reject()),
            ProtocolFrame::OpenRequest(OpenRequest {
                request_id,
                deadline_ms: 1500,
                head: request_head(),
            }),
            ProtocolFrame::RequestBodyChunk(RequestBodyChunk {
                request_id,
                chunk: b"hello ".to_vec(),
            }),
            ProtocolFrame::RequestEnd(RequestEnd {
                request_id,
                trailers: BridgeHeaders::new([("X-Trailer".to_string(), "1".to_string())])
                    .expect("trailers"),
            }),
            ProtocolFrame::ResponseHead(ResponseHeadFrame {
                request_id,
                head: response_head(),
            }),
            ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                request_id,
                chunk: b"world".to_vec(),
            }),
            ProtocolFrame::ResponseEnd(ResponseEnd {
                request_id,
                trailers: BridgeHeaders::default(),
            }),
            ProtocolFrame::Cancel(Cancel {
                request_id,
                code: AbiErrorCode::Cancelled,
                message: "client went away".to_string(),
            }),
            ProtocolFrame::Error(ErrorFrame {
                request_id: Some(request_id),
                fatal: false,
                code: AbiErrorCode::LimitExceeded,
                message: "too much".to_string(),
            }),
            ProtocolFrame::Error(ErrorFrame {
                request_id: None,
                fatal: true,
                code: AbiErrorCode::InvalidRequest,
                message: "bad frame".to_string(),
            }),
        ];
        for frame in frames {
            let encoded = frame.encode(&limits).expect("encode");
            assert_eq!(encoded[0], frame.tag());
            assert_eq!(
                u32::from_le_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]) as usize,
                encoded.len() - PROTO_FRAME_HEADER_BYTES
            );
            let (decoded, consumed) = ProtocolFrame::decode(&encoded, &limits).expect("decode");
            assert_eq!(
                decoded,
                frame,
                "round-trip differs for tag {:#04x}",
                frame.tag()
            );
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn frame_tags_are_in_the_external_range_and_disjoint_from_in_process_abi() {
        let request_id = RequestId::new(1).expect("id");
        let tags = [
            ProtocolFrame::Hello(make_hello(Vec::new())).tag(),
            ProtocolFrame::HelloAck(HelloAck {
                protocol: PROTOCOL_VERSION,
                abi: NegotiatedAbi {
                    plugin: AbiVersion::ABI_1_0,
                    host: HOST_ABI_VERSION,
                },
                granted: CapabilitySet::EMPTY,
                limits: PluginLimits::default_limits(),
                max_in_flight_requests: 1,
                body_window_bytes: 1,
            })
            .tag(),
            ProtocolFrame::Reject(HandshakeError::InvalidConfig { reason: "x" }.to_reject()).tag(),
            ProtocolFrame::OpenRequest(OpenRequest {
                request_id,
                deadline_ms: 0,
                head: request_head(),
            })
            .tag(),
            ProtocolFrame::RequestBodyChunk(RequestBodyChunk {
                request_id,
                chunk: Vec::new(),
            })
            .tag(),
            ProtocolFrame::RequestEnd(RequestEnd {
                request_id,
                trailers: BridgeHeaders::default(),
            })
            .tag(),
            ProtocolFrame::ResponseHead(ResponseHeadFrame {
                request_id,
                head: response_head(),
            })
            .tag(),
            ProtocolFrame::ResponseBodyChunk(ResponseBodyChunk {
                request_id,
                chunk: Vec::new(),
            })
            .tag(),
            ProtocolFrame::ResponseEnd(ResponseEnd {
                request_id,
                trailers: BridgeHeaders::default(),
            })
            .tag(),
            ProtocolFrame::Cancel(Cancel {
                request_id,
                code: AbiErrorCode::Cancelled,
                message: String::new(),
            })
            .tag(),
            ProtocolFrame::Error(ErrorFrame::from_protocol_error(
                &ProtocolError::ZeroRequestId,
            ))
            .tag(),
        ];
        for tag in tags {
            assert!(
                (FIRST_PROTOCOL_TAG..=LAST_PROTOCOL_TAG).contains(&tag),
                "tag {tag:#04x} outside external range"
            );
            assert!(!(1..=9).contains(&tag), "tag {tag} overlaps in-process ABI");
        }
    }

    #[test]
    fn in_process_and_unknown_tags_are_typed_errors() {
        let limits = AbiLimits::spec_defaults();
        let mut frame = Writer::new();
        frame.u8(1); // in-process FRAME_REQUEST_HEAD
        frame.u32(0);
        let bytes = frame.into_vec();
        assert_eq!(
            ProtocolFrame::decode(&bytes, &limits),
            Err(ProtocolError::InProcessFrameTag { tag: 1 })
        );

        let mut frame = Writer::new();
        frame.u8(0xF0);
        frame.u32(0);
        let bytes = frame.into_vec();
        assert!(matches!(
            ProtocolFrame::decode(&bytes, &limits),
            Err(ProtocolError::Wire(WireError::UnknownFrameTag {
                tag: 0xF0
            }))
        ));
    }

    #[test]
    fn malformed_frames_never_panic() {
        let limits = AbiLimits::spec_defaults();
        let valid = ProtocolFrame::OpenRequest(OpenRequest {
            request_id: RequestId::new(5).expect("id"),
            deadline_ms: 0,
            head: request_head(),
        })
        .encode(&limits)
        .expect("encode");
        // Truncations.
        for length in 0..valid.len() {
            let error = ProtocolFrame::decode(&valid[..length], &limits).expect_err("truncated");
            // Must be a typed protocol error; no panic.
            let _ = error.abi_code();
        }
        // Corrupted bytes.
        for index in 0..valid.len() {
            let mut corrupted = valid.clone();
            corrupted[index] ^= 0xFF;
            if let Ok((frame, _)) = ProtocolFrame::decode(&corrupted, &limits) {
                let _ = frame.tag();
            }
        }
        // Oversized declared payload.
        let mut oversized = Writer::new();
        oversized.u8(PROTO_FRAME_ERROR);
        oversized.u32(u32::MAX);
        assert!(matches!(
            ProtocolFrame::decode(&oversized.into_vec(), &limits),
            Err(ProtocolError::Wire(WireError::FrameTooLarge { .. }))
        ));
        // Trailing bytes belong to the next frame: decode succeeds and reports the consumed
        // length; the leftover byte on its own is an empty/truncated frame error.
        let mut trailing = valid.clone();
        trailing.push(0xAB);
        let (_, consumed) = ProtocolFrame::decode(&trailing, &limits).expect("first frame");
        assert_eq!(consumed, valid.len());
        assert!(ProtocolFrame::decode(&trailing[consumed..], &limits).is_err());
        // Zero request id.
        let mut zero = Writer::new();
        zero.u8(PROTO_FRAME_REQUEST_BODY_CHUNK);
        zero.u32(8 + 4);
        zero.u64(0);
        zero.bytes("body chunk", b"test").expect("chunk");
        assert_eq!(
            ProtocolFrame::decode(&zero.into_vec(), &limits),
            Err(ProtocolError::ZeroRequestId)
        );
    }

    #[test]
    fn handshake_errors_map_to_reject_frames_that_round_trip() {
        let limits = AbiLimits::spec_defaults();
        let error = HandshakeError::Capability(CapabilityError::NotGranted {
            capability: Capability::HttpClient,
        });
        let reject = error.to_reject();
        let frame = ProtocolFrame::Reject(reject.clone());
        let bytes = frame.encode(&limits).expect("encode reject");
        let (decoded, _) = ProtocolFrame::decode(&bytes, &limits).expect("decode reject");
        assert_eq!(decoded, frame);
        if let ProtocolFrame::Reject(decoded) = decoded {
            assert_eq!(decoded.phase, RejectPhase::Capability);
            assert_eq!(decoded.code, AbiErrorCode::CapabilityDenied);
        }
    }

    #[test]
    fn tighten_limits_is_element_wise_minimum() {
        let requested = PluginLimits {
            max_request_body_bytes: 10,
            max_response_body_bytes: 20,
            max_host_calls_per_request: 30,
            max_memory_bytes: 40,
        };
        let host = PluginLimits {
            max_request_body_bytes: 5,
            max_response_body_bytes: 25,
            max_host_calls_per_request: 15,
            max_memory_bytes: 35,
        };
        assert_eq!(
            tighten_limits(&requested, &host),
            PluginLimits {
                max_request_body_bytes: 5,
                max_response_body_bytes: 20,
                max_host_calls_per_request: 15,
                max_memory_bytes: 35,
            }
        );
    }

    #[test]
    fn abort_mapping_uses_stable_abi_codes() {
        assert_eq!(
            ProtocolError::ZeroRequestId.abi_code(),
            AbiErrorCode::InvalidRequest
        );
        assert_eq!(
            ProtocolError::UnknownFrameTag { tag: 0xEE }.abi_code(),
            AbiErrorCode::Unsupported
        );
        assert_eq!(
            ProtocolError::Handshake(HandshakeError::Capability(CapabilityError::NotGranted {
                capability: Capability::Log
            }))
            .abi_code(),
            AbiErrorCode::CapabilityDenied
        );
        assert_eq!(
            ProtocolError::Wire(WireError::FrameTooLarge { len: 1, max: 0 }).abi_code(),
            AbiErrorCode::InvalidRequest
        );
    }
}
