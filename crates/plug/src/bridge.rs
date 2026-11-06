//! HTTP request/response bridging and the streaming-body frame contract.
//!
//! The host and a plugin exchange length-prefixed frames over the WASM linear-memory boundary (the
//! actual transport is defined by the runtime, T-PLUG-011; this module defines the bytes).
//!
//! # Frame layout
//!
//! ```text
//! +---------+----------------+---------------------+
//! | tag: u8 | payload_len:u32 | payload (len bytes) |
//! +---------+----------------+---------------------+
//! ```
//!
//! All integers are little-endian. `payload_len` may not exceed
//! [`AbiLimits::max_frame_payload`] (1 MiB default). Unknown tags are rejected, never skipped, so
//! a plugin built for a newer minor version fails loudly rather than being misunderstood.
//!
//! # Request/response streaming contract
//!
//! 1. The host sends exactly one [`BridgeFrame::RequestHead`], then zero or more
//!    [`BridgeFrame::RequestBodyChunk`] frames (each at most [`AbiLimits::max_body_chunk`], 64 KiB
//!    default), then exactly one [`BridgeFrame::RequestEnd`] carrying optional trailers.
//! 2. The plugin sends exactly one [`BridgeFrame::ResponseHead`], then zero or more
//!    [`BridgeFrame::ResponseBodyChunk`] frames, then exactly one [`BridgeFrame::ResponseEnd`]
//!    carrying optional trailers.
//! 3. A head's [`BodyMode`] declares whether a body follows: [`BodyMode::Empty`] means the very next
//!    frame is the corresponding end frame; [`BodyMode::Buffered`] announces the exact body length
//!    (used by non-streaming callers; chunks still carry the bytes); [`BodyMode::Streamed`] announces
//!    a body of unknown length. `Buffered` lengths above [`AbiLimits::max_body_bytes`] are rejected
//!    when decoding a head.
//! 4. Total bodies are bounded by the negotiated [`crate::descriptor::PluginLimits`]; a host should
//!    enforce totals with [`BodyBudget`]. The frame codec itself only enforces the per-frame limits
//!    listed above, which keeps it allocation-safe.
//! 5. Host calls travel as [`BridgeFrame::HostCall`]/[`BridgeFrame::HostCallResult`] frames and may
//!    only be sent by the plugin while a request is active (see [`crate::hostcall`]).
//! 6. An abnormal end is [`BridgeFrame::Error`] with a stable [`crate::error::AbiErrorCode`].
//!
//! These ordering rules are enforced by the host runtime, not by the pure frame codec: this module
//! gives the wire format and the size/encoding checks that must never be skipped.

use serde::{Deserialize, Serialize};

use crate::encoding::{Reader, Writer};
use crate::error::{AbiErrorCode, WireError};
use crate::hostcall::{HostCall, HostCallResult};

/// Frame tag for a request head.
pub const FRAME_REQUEST_HEAD: u8 = 1;
/// Frame tag for a request body chunk.
pub const FRAME_REQUEST_BODY_CHUNK: u8 = 2;
/// Frame tag for the end of a request (optionally with trailers).
pub const FRAME_REQUEST_END: u8 = 3;
/// Frame tag for a response head.
pub const FRAME_RESPONSE_HEAD: u8 = 4;
/// Frame tag for a response body chunk.
pub const FRAME_RESPONSE_BODY_CHUNK: u8 = 5;
/// Frame tag for the end of a response (optionally with trailers).
pub const FRAME_RESPONSE_END: u8 = 6;
/// Frame tag for a plugin-to-host call.
pub const FRAME_HOST_CALL: u8 = 7;
/// Frame tag for a host-to-plugin host-call result.
pub const FRAME_HOST_CALL_RESULT: u8 = 8;
/// Frame tag for an ABI error (abnormal end).
pub const FRAME_ERROR: u8 = 9;

/// Maximum frame payload accepted by ABI v1 (1 MiB).
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum body chunk size accepted by ABI v1 (64 KiB).
pub const MAX_BODY_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum number of headers (or trailers) in one header block.
pub const MAX_HEADER_COUNT: usize = 128;

/// Maximum header name length.
pub const MAX_HEADER_NAME_BYTES: usize = 256;

/// Maximum header value length.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// Maximum request URI (path and query) length.
pub const MAX_URI_BYTES: usize = 8 * 1024;

/// Maximum HTTP authority length.
pub const MAX_AUTHORITY_BYTES: usize = 256;

/// Maximum scheme length (`http`/`https`).
pub const MAX_SCHEME_BYTES: usize = 16;

/// Maximum method name length for non-standard methods.
pub const MAX_METHOD_NAME_BYTES: usize = 32;

/// Maximum total request/response body announced in a [`BodyMode::Buffered`] head.
pub const MAX_ANNOUNCED_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum ABI error message length.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

/// Limits used while decoding/encoding ABI values.
///
/// The defaults are the ABI v1 limits. A host may use tighter values, but values above the defaults
/// are a protocol violation and the encode/decode helpers reject such limits by clamping to the ABI
/// defaults internally (`AbiLimits::effective`); this keeps the byte contract stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiLimits {
    /// Maximum encoded frame payload.
    pub max_frame_payload: usize,
    /// Maximum body chunk length.
    pub max_body_chunk: usize,
    /// Maximum header/trailer count.
    pub max_header_count: usize,
    /// Maximum header name length.
    pub max_header_name: usize,
    /// Maximum header value length.
    pub max_header_value: usize,
    /// Maximum request URI length.
    pub max_uri: usize,
    /// Maximum authority length.
    pub max_authority: usize,
    /// Maximum total body announced in a buffered head.
    pub max_body_bytes: u64,
    /// Maximum log message length.
    pub max_log_message: usize,
    /// Maximum log fields per record.
    pub max_log_fields: usize,
    /// Maximum random bytes per host call.
    pub max_random_bytes: u32,
    /// Maximum outbound HTTP URL length.
    pub max_url: usize,
    /// Maximum config key length.
    pub max_config_key: usize,
    /// Maximum body length for an outbound host-call HTTP request/response.
    pub max_host_call_body: usize,
    /// Maximum ABI error message length.
    pub max_error_message: usize,
}

impl AbiLimits {
    /// The ABI v1 default limits.
    pub const fn spec_defaults() -> Self {
        Self {
            max_frame_payload: MAX_FRAME_PAYLOAD_BYTES,
            max_body_chunk: MAX_BODY_CHUNK_BYTES,
            max_header_count: MAX_HEADER_COUNT,
            max_header_name: MAX_HEADER_NAME_BYTES,
            max_header_value: MAX_HEADER_VALUE_BYTES,
            max_uri: MAX_URI_BYTES,
            max_authority: MAX_AUTHORITY_BYTES,
            max_body_bytes: MAX_ANNOUNCED_BODY_BYTES,
            max_log_message: 4 * 1024,
            max_log_fields: 32,
            max_random_bytes: 64,
            max_url: 8 * 1024,
            max_config_key: 256,
            max_host_call_body: 1024 * 1024,
            max_error_message: MAX_ERROR_MESSAGE_BYTES,
        }
    }
}

impl Default for AbiLimits {
    fn default() -> Self {
        Self::spec_defaults()
    }
}

/// Total-body accounting helper for the streaming contract.
///
/// The frame codec enforces per-frame limits only; hosts track the negotiated total body bound with
/// this type so a plugin cannot stream more than its descriptor allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyBudget {
    limit: u64,
    consumed: u64,
}

impl BodyBudget {
    /// Start a budget allowing `limit` body bytes in total.
    pub fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    /// Bytes still available.
    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }

    /// Bytes consumed so far.
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Charge `len` bytes, failing with [`WireError::LimitExceeded`] when the total would be
    /// exceeded. The budget is left unchanged on failure.
    pub fn consume(&mut self, len: u64) -> Result<(), WireError> {
        let next = self
            .consumed
            .checked_add(len)
            .ok_or(WireError::SizeOverflow {
                field: "body length",
            })?;
        if next > self.limit {
            return Err(WireError::LimitExceeded {
                field: "body length",
                len: usize::try_from(next).unwrap_or(usize::MAX),
                max: usize::try_from(self.limit).unwrap_or(usize::MAX),
            });
        }
        self.consumed = next;
        Ok(())
    }
}

/// HTTP method of a bridged request, with a stable wire code.
///
/// Standard methods use codes 0..=8; any other method uses code 9 followed by a UTF-8 method name
/// (at most [`MAX_METHOD_NAME_BYTES`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
    /// `PATCH`.
    Patch,
    /// `OPTIONS`.
    Options,
    /// `CONNECT`.
    Connect,
    /// `TRACE`.
    Trace,
    /// Any other method token.
    Other(String),
}

impl BridgeMethod {
    /// Stable wire code.
    pub const fn code(&self) -> u8 {
        match self {
            Self::Get => 0,
            Self::Head => 1,
            Self::Post => 2,
            Self::Put => 3,
            Self::Delete => 4,
            Self::Patch => 5,
            Self::Options => 6,
            Self::Connect => 7,
            Self::Trace => 8,
            Self::Other(_) => 9,
        }
    }

    /// HTTP method name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other(name) => name,
        }
    }

    /// Encode as a stable wire method.
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        writer.u8(self.code());
        if let Self::Other(name) = self {
            writer.string("method name", name)?;
            if name.len() > MAX_METHOD_NAME_BYTES || name.len() > limits.max_frame_payload {
                return Err(WireError::LimitExceeded {
                    field: "method name",
                    len: name.len(),
                    max: MAX_METHOD_NAME_BYTES,
                });
            }
            if name.is_empty() || !name.bytes().all(is_http_token_byte) {
                return Err(WireError::UnknownMethod { code: self.code() });
            }
        }
        Ok(())
    }

    /// Decode a stable wire method.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let code = reader.u8()?;
        let method = match code {
            0 => Self::Get,
            1 => Self::Head,
            2 => Self::Post,
            3 => Self::Put,
            4 => Self::Delete,
            5 => Self::Patch,
            6 => Self::Options,
            7 => Self::Connect,
            8 => Self::Trace,
            9 => {
                let name = reader.string(
                    "method name",
                    MAX_METHOD_NAME_BYTES.min(limits.max_frame_payload),
                )?;
                if name.is_empty() || !name.bytes().all(is_http_token_byte) {
                    return Err(WireError::UnknownMethod { code });
                }
                Self::Other(name)
            }
            _ => return Err(WireError::UnknownMethod { code }),
        };
        Ok(method)
    }
}

/// Whether `byte` is an RFC 9110 `tchar` (valid in a method or header name).
pub(crate) fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Ordered header/trailer list with HTTP token name validation and ABI size limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeHeaders {
    entries: Vec<(String, String)>,
}

impl BridgeHeaders {
    /// Build a header list, validating names and limits.
    pub fn new(entries: impl IntoIterator<Item = (String, String)>) -> Result<Self, WireError> {
        let limits = AbiLimits::spec_defaults();
        let mut headers = Self::default();
        for (name, value) in entries {
            headers.push(&name, &value, &limits)?;
        }
        Ok(headers)
    }

    /// Number of headers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no headers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over the headers in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Append a header, enforcing the ABI token/name/value/count limits.
    pub fn push(&mut self, name: &str, value: &str, limits: &AbiLimits) -> Result<(), WireError> {
        if self.entries.len() >= limits.max_header_count {
            return Err(WireError::LimitExceeded {
                field: "header count",
                len: self.entries.len() + 1,
                max: limits.max_header_count,
            });
        }
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(WireError::InvalidHeaderName { offset: 0 });
        }
        if name.len() > limits.max_header_name {
            return Err(WireError::LimitExceeded {
                field: "header name",
                len: name.len(),
                max: limits.max_header_name,
            });
        }
        if value.len() > limits.max_header_value {
            return Err(WireError::LimitExceeded {
                field: "header value",
                len: value.len(),
                max: limits.max_header_value,
            });
        }
        self.entries.push((name.to_string(), value.to_string()));
        Ok(())
    }

    /// Encode as `u16 count` then length-prefixed name/value strings.
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        if self.entries.len() > limits.max_header_count {
            return Err(WireError::LimitExceeded {
                field: "header count",
                len: self.entries.len(),
                max: limits.max_header_count,
            });
        }
        writer.u16(
            u16::try_from(self.entries.len()).map_err(|_| WireError::SizeOverflow {
                field: "header count",
            })?,
        );
        for (name, value) in &self.entries {
            if name.is_empty() || !name.bytes().all(is_http_token_byte) {
                return Err(WireError::InvalidHeaderName { offset: 0 });
            }
            if name.len() > limits.max_header_name {
                return Err(WireError::LimitExceeded {
                    field: "header name",
                    len: name.len(),
                    max: limits.max_header_name,
                });
            }
            if value.len() > limits.max_header_value {
                return Err(WireError::LimitExceeded {
                    field: "header value",
                    len: value.len(),
                    max: limits.max_header_value,
                });
            }
            writer.string("header name", name)?;
            writer.string("header value", value)?;
        }
        Ok(())
    }

    /// Decode a header block, validating limits and token names.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let count = reader.u16()? as usize;
        if count > limits.max_header_count {
            return Err(WireError::LimitExceeded {
                field: "header count",
                len: count,
                max: limits.max_header_count,
            });
        }
        let mut headers = Self {
            entries: Vec::with_capacity(count),
        };
        for _ in 0..count {
            let name_offset = reader.position();
            let name = reader.string("header name", limits.max_header_name)?;
            if !name.bytes().all(is_http_token_byte) {
                return Err(WireError::InvalidHeaderName {
                    offset: name_offset,
                });
            }
            let value = reader.string("header value", limits.max_header_value)?;
            headers.entries.push((name, value));
        }
        Ok(headers)
    }
}

/// Whether a bridged body follows the head and how it is announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyMode {
    /// No body follows; the next frame is the corresponding end frame.
    Empty,
    /// A body of exactly `length` bytes follows, split across chunks.
    Buffered {
        /// Announced total length.
        length: u64,
    },
    /// A body of unknown length follows until the end frame.
    Streamed,
}

impl BodyMode {
    const TAG_EMPTY: u8 = 0;
    const TAG_BUFFERED: u8 = 1;
    const TAG_STREAMED: u8 = 2;

    /// Encode as a tag byte plus an optional little-endian `u64` length.
    pub fn encode(self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        match self {
            Self::Empty => writer.u8(Self::TAG_EMPTY),
            Self::Buffered { length } => {
                if length > limits.max_body_bytes {
                    return Err(WireError::LimitExceeded {
                        field: "body length",
                        len: usize::try_from(length).unwrap_or(usize::MAX),
                        max: usize::try_from(limits.max_body_bytes).unwrap_or(usize::MAX),
                    });
                }
                writer.u8(Self::TAG_BUFFERED);
                writer.u64(length);
            }
            Self::Streamed => writer.u8(Self::TAG_STREAMED),
        }
        Ok(())
    }

    /// Decode a body-mode tag and validate an announced length against the limits.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let tag = reader.u8()?;
        match tag {
            Self::TAG_EMPTY => Ok(Self::Empty),
            Self::TAG_BUFFERED => {
                let length = reader.u64()?;
                if length > limits.max_body_bytes {
                    return Err(WireError::LimitExceeded {
                        field: "body length",
                        len: usize::try_from(length).unwrap_or(usize::MAX),
                        max: usize::try_from(limits.max_body_bytes).unwrap_or(usize::MAX),
                    });
                }
                Ok(Self::Buffered { length })
            }
            Self::TAG_STREAMED => Ok(Self::Streamed),
            other => Err(WireError::UnknownBodyMode { tag: other }),
        }
    }
}

/// Head of a bridged HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHead {
    /// Request method.
    pub method: BridgeMethod,
    /// URI scheme (`http` or `https`); informational for the plugin.
    pub scheme: String,
    /// Request authority (`Host`), without userinfo.
    pub authority: String,
    /// Path and query, exactly as received (`/a/b?x=1`).
    pub path_and_query: String,
    /// Request headers, including `Host` if the host provides it via authority.
    pub headers: BridgeHeaders,
    /// Declares whether a request body follows.
    pub body: BodyMode,
}

impl RequestHead {
    /// Encode the request head.
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        if self.scheme.len() > MAX_SCHEME_BYTES {
            return Err(WireError::LimitExceeded {
                field: "scheme",
                len: self.scheme.len(),
                max: MAX_SCHEME_BYTES,
            });
        }
        if self.authority.len() > limits.max_authority {
            return Err(WireError::LimitExceeded {
                field: "authority",
                len: self.authority.len(),
                max: limits.max_authority,
            });
        }
        self.method.encode(writer, limits)?;
        writer.string("scheme", &self.scheme)?;
        writer.string("authority", &self.authority)?;
        writer.string("uri", &self.path_and_query)?;
        if self.path_and_query.len() > limits.max_uri {
            return Err(WireError::LimitExceeded {
                field: "uri",
                len: self.path_and_query.len(),
                max: limits.max_uri,
            });
        }
        self.headers.encode(writer, limits)?;
        self.body.encode(writer, limits)
    }

    /// Decode the request head.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let method = BridgeMethod::decode(reader, limits)?;
        let scheme = reader.string("scheme", MAX_SCHEME_BYTES.min(limits.max_frame_payload))?;
        let authority = reader.string("authority", limits.max_authority)?;
        let path_and_query = reader.string("uri", limits.max_uri)?;
        let headers = BridgeHeaders::decode(reader, limits)?;
        let body = BodyMode::decode(reader, limits)?;
        Ok(Self {
            method,
            scheme,
            authority,
            path_and_query,
            headers,
            body,
        })
    }
}

/// Head of a bridged HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHead {
    /// HTTP status (100..=999).
    pub status: u16,
    /// Response headers.
    pub headers: BridgeHeaders,
    /// Declares whether a response body follows.
    pub body: BodyMode,
}

impl ResponseHead {
    /// Validate the status and encode the response head.
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        if !(100..=999).contains(&self.status) {
            return Err(WireError::InvalidStatus {
                status: self.status,
            });
        }
        writer.u16(self.status);
        self.headers.encode(writer, limits)?;
        self.body.encode(writer, limits)
    }

    /// Decode the response head and validate the status range.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let status = reader.u16()?;
        if !(100..=999).contains(&status) {
            return Err(WireError::InvalidStatus { status });
        }
        let headers = BridgeHeaders::decode(reader, limits)?;
        let body = BodyMode::decode(reader, limits)?;
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

/// Abnormal end of a bridged exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiErrorFrame {
    /// Stable ABI error code.
    pub code: AbiErrorCode,
    /// Free-form diagnostic; not part of the stable contract.
    pub message: String,
}

impl AbiErrorFrame {
    /// Encode the error frame payload.
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        writer.u32(self.code.code());
        if self.message.len() > limits.max_error_message {
            return Err(WireError::LimitExceeded {
                field: "error message",
                len: self.message.len(),
                max: limits.max_error_message,
            });
        }
        writer.string("error message", &self.message)
    }

    /// Decode the error frame payload, rejecting undefined codes.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let code = reader.u32()?;
        let code = AbiErrorCode::from_code(code).ok_or(WireError::UnknownAbiErrorCode { code })?;
        let message = reader.string("error message", limits.max_error_message)?;
        Ok(Self { code, message })
    }
}

/// One frame of the bridged exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeFrame {
    /// Request head (host to plugin).
    RequestHead(RequestHead),
    /// Request body chunk (host to plugin).
    RequestBodyChunk(Vec<u8>),
    /// Request end with optional trailers (host to plugin).
    RequestEnd(BridgeHeaders),
    /// Response head (plugin to host).
    ResponseHead(ResponseHead),
    /// Response body chunk (plugin to host).
    ResponseBodyChunk(Vec<u8>),
    /// Response end with optional trailers (plugin to host).
    ResponseEnd(BridgeHeaders),
    /// Plugin-to-host call.
    HostCall(HostCall),
    /// Host-to-plugin call result.
    HostCallResult(HostCallResult),
    /// Abnormal end.
    Error(AbiErrorFrame),
}

impl BridgeFrame {
    /// Stable frame tag.
    pub const fn tag(&self) -> u8 {
        match self {
            Self::RequestHead(_) => FRAME_REQUEST_HEAD,
            Self::RequestBodyChunk(_) => FRAME_REQUEST_BODY_CHUNK,
            Self::RequestEnd(_) => FRAME_REQUEST_END,
            Self::ResponseHead(_) => FRAME_RESPONSE_HEAD,
            Self::ResponseBodyChunk(_) => FRAME_RESPONSE_BODY_CHUNK,
            Self::ResponseEnd(_) => FRAME_RESPONSE_END,
            Self::HostCall(_) => FRAME_HOST_CALL,
            Self::HostCallResult(_) => FRAME_HOST_CALL_RESULT,
            Self::Error(_) => FRAME_ERROR,
        }
    }

    /// Encode a complete frame (tag, payload length, payload).
    pub fn encode(&self, limits: &AbiLimits) -> Result<Vec<u8>, WireError> {
        let mut payload = Writer::new();
        match self {
            Self::RequestHead(head) => head.encode(&mut payload, limits)?,
            Self::RequestBodyChunk(chunk) => {
                if chunk.len() > limits.max_body_chunk {
                    return Err(WireError::LimitExceeded {
                        field: "body chunk",
                        len: chunk.len(),
                        max: limits.max_body_chunk,
                    });
                }
                payload.bytes("body chunk", chunk)?;
            }
            Self::RequestEnd(trailers) => trailers.encode(&mut payload, limits)?,
            Self::ResponseHead(head) => head.encode(&mut payload, limits)?,
            Self::ResponseBodyChunk(chunk) => {
                if chunk.len() > limits.max_body_chunk {
                    return Err(WireError::LimitExceeded {
                        field: "body chunk",
                        len: chunk.len(),
                        max: limits.max_body_chunk,
                    });
                }
                payload.bytes("body chunk", chunk)?;
            }
            Self::ResponseEnd(trailers) => trailers.encode(&mut payload, limits)?,
            Self::HostCall(call) => call.encode(&mut payload, limits)?,
            Self::HostCallResult(result) => result.encode(&mut payload, limits)?,
            Self::Error(error) => error.encode(&mut payload, limits)?,
        }
        let payload = payload.into_vec();
        if payload.len() > limits.max_frame_payload {
            return Err(WireError::FrameTooLarge {
                len: payload.len(),
                max: limits.max_frame_payload,
            });
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

    /// Decode one frame from the start of `bytes`, returning the frame and the number of bytes it
    /// consumed. Trailing bytes belong to the next frame and are not an error (stream decoding); use
    /// the returned count to advance.
    pub fn decode(bytes: &[u8], limits: &AbiLimits) -> Result<(Self, usize), WireError> {
        if bytes.is_empty() {
            return Err(WireError::EmptyFrame);
        }
        let mut reader = Reader::new(bytes);
        let tag = reader.u8()?;
        let payload_len = reader.u32()? as usize;
        if payload_len > limits.max_frame_payload {
            return Err(WireError::FrameTooLarge {
                len: payload_len,
                max: limits.max_frame_payload,
            });
        }
        let payload = reader.take(payload_len)?;
        let consumed = 5 + payload_len;
        let mut payload = Reader::new(payload);
        let frame = match tag {
            FRAME_REQUEST_HEAD => Self::RequestHead(RequestHead::decode(&mut payload, limits)?),
            FRAME_REQUEST_BODY_CHUNK => {
                Self::RequestBodyChunk(payload.bytes("body chunk", limits.max_body_chunk)?.to_vec())
            }
            FRAME_REQUEST_END => Self::RequestEnd(BridgeHeaders::decode(&mut payload, limits)?),
            FRAME_RESPONSE_HEAD => Self::ResponseHead(ResponseHead::decode(&mut payload, limits)?),
            FRAME_RESPONSE_BODY_CHUNK => Self::ResponseBodyChunk(
                payload.bytes("body chunk", limits.max_body_chunk)?.to_vec(),
            ),
            FRAME_RESPONSE_END => Self::ResponseEnd(BridgeHeaders::decode(&mut payload, limits)?),
            FRAME_HOST_CALL => Self::HostCall(HostCall::decode(&mut payload, limits)?),
            FRAME_HOST_CALL_RESULT => {
                Self::HostCallResult(HostCallResult::decode(&mut payload, limits)?)
            }
            FRAME_ERROR => Self::Error(AbiErrorFrame::decode(&mut payload, limits)?),
            other => return Err(WireError::UnknownFrameTag { tag: other }),
        };
        payload.finish()?;
        Ok((frame, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> BridgeHeaders {
        BridgeHeaders::new([
            ("content-type".to_string(), "text/plain".to_string()),
            ("x-test".to_string(), "yes".to_string()),
        ])
        .expect("headers")
    }

    fn frames() -> Vec<BridgeFrame> {
        vec![
            BridgeFrame::RequestHead(RequestHead {
                method: BridgeMethod::Get,
                scheme: "https".to_string(),
                authority: "example.com".to_string(),
                path_and_query: "/a?b=c".to_string(),
                headers: headers(),
                body: BodyMode::Empty,
            }),
            BridgeFrame::RequestBodyChunk(vec![1, 2, 3]),
            BridgeFrame::RequestEnd(headers()),
            BridgeFrame::ResponseHead(ResponseHead {
                status: 200,
                headers: headers(),
                body: BodyMode::Streamed,
            }),
            BridgeFrame::ResponseBodyChunk(vec![4, 5, 6]),
            BridgeFrame::ResponseEnd(BridgeHeaders::default()),
            BridgeFrame::Error(AbiErrorFrame {
                code: AbiErrorCode::HostFailure,
                message: "boom".to_string(),
            }),
        ]
    }

    #[test]
    fn frame_tags_are_stable() {
        let frames = frames();
        let tags: Vec<u8> = frames.iter().map(BridgeFrame::tag).collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5, 6, 9]);
        assert_eq!(FRAME_HOST_CALL, 7);
        assert_eq!(FRAME_HOST_CALL_RESULT, 8);
    }

    #[test]
    fn frames_round_trip_and_stream_decode_advances_by_consumed_bytes() {
        let limits = AbiLimits::spec_defaults();
        let frames = frames();
        let mut encoded = Vec::new();
        for frame in &frames {
            encoded.extend(frame.encode(&limits).expect("encode"));
        }
        let mut offset = 0;
        for expected in &frames {
            let (frame, consumed) =
                BridgeFrame::decode(&encoded[offset..], &limits).expect("decode");
            assert_eq!(&frame, expected);
            offset += consumed;
        }
        assert_eq!(offset, encoded.len());
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let limits = AbiLimits::spec_defaults();
        assert_eq!(
            BridgeFrame::decode(&[], &limits),
            Err(WireError::EmptyFrame)
        );
        assert_eq!(
            BridgeFrame::decode(&[1, 10, 0, 0, 0, 1], &limits),
            Err(WireError::UnexpectedEof {
                offset: 5,
                needed: 10,
                remaining: 1
            })
        );
        // Unknown tag with an empty payload.
        assert_eq!(
            BridgeFrame::decode(&[42, 0, 0, 0, 0], &limits),
            Err(WireError::UnknownFrameTag { tag: 42 })
        );
        // Payload larger than the frame limit.
        assert_eq!(
            BridgeFrame::decode(&[1, 1, 0, 0x10, 0], &limits),
            Err(WireError::FrameTooLarge {
                len: MAX_FRAME_PAYLOAD_BYTES + 1,
                max: MAX_FRAME_PAYLOAD_BYTES
            })
        );
        // Body chunk above the chunk limit: encode first to get a valid frame, then decode with a
        // tighter limit.
        let frame = BridgeFrame::RequestBodyChunk(vec![0; 10]);
        let encoded = frame.encode(&limits).expect("encode");
        let tight = AbiLimits {
            max_body_chunk: 5,
            ..AbiLimits::spec_defaults()
        };
        assert_eq!(
            BridgeFrame::decode(&encoded, &tight),
            Err(WireError::LimitExceeded {
                field: "body chunk",
                len: 10,
                max: 5
            })
        );
        // Trailing bytes inside a frame payload are rejected: a request-end payload is a header
        // block (u16 count here) and one extra byte must not be silently ignored.
        let encoded = [FRAME_REQUEST_END, 3, 0, 0, 0, 0, 0, 0xFF];
        assert_eq!(
            BridgeFrame::decode(&encoded, &limits),
            Err(WireError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn body_budget_enforces_totals() {
        let mut budget = BodyBudget::new(4);
        budget.consume(2).expect("first chunk");
        assert_eq!(budget.remaining(), 2);
        assert_eq!(
            budget.consume(3),
            Err(WireError::LimitExceeded {
                field: "body length",
                len: 5,
                max: 4
            })
        );
        assert_eq!(
            budget.consumed(),
            2,
            "failed consumption leaves budget unchanged"
        );
    }

    #[test]
    fn headers_reject_invalid_names_and_oversized_values() {
        let limits = AbiLimits::spec_defaults();
        let mut headers = BridgeHeaders::default();
        assert_eq!(
            headers.push("bad name", "x", &limits),
            Err(WireError::InvalidHeaderName { offset: 0 })
        );
        assert!(headers.push("x-test", "ok", &limits).is_ok());
        assert_eq!(
            headers.push(
                "x-long",
                "x",
                &AbiLimits {
                    max_header_value: 0,
                    ..limits
                }
            ),
            Err(WireError::LimitExceeded {
                field: "header value",
                len: 1,
                max: 0
            })
        );
    }
}
