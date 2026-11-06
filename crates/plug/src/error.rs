//! Typed error model for the plugin host ABI.
//!
//! Every fallible operation in this crate returns a typed error instead of panicking or returning
//! a bare string: negotiating versions, validating descriptors, granting capabilities, authorising
//! host calls and decoding wire frames all have a dedicated error enum. The enums carry the
//! offending values (version numbers, capability codes, offsets, limits) so a host can log a
//! located, actionable diagnostic and, where applicable, report a stable [`AbiErrorCode`] to the
//! plugin. Error type names, variants and [`AbiErrorCode`] values are part of the ABI contract; the
//! messages are not.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;

/// Version negotiation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    /// The host ABI major version is newer than the plugin's: the plugin was built for an older,
    /// incompatible ABI.
    HostMajorNewer {
        /// Host (runtime) ABI major version.
        host_major: u16,
        /// Plugin ABI major version.
        plugin_major: u16,
    },
    /// The plugin ABI major version is newer than the host's: the plugin requires features this
    /// host does not implement.
    PluginMajorNewer {
        /// Host (runtime) ABI major version.
        host_major: u16,
        /// Plugin ABI major version.
        plugin_major: u16,
    },
    /// Same major version, but the plugin needs a newer minor version than the host provides.
    /// Minor versions are additive: the host must be at least as new as the plugin.
    PluginMinorNewer {
        /// Host (runtime) ABI minor version.
        host_minor: u16,
        /// Plugin ABI minor version.
        plugin_minor: u16,
    },
    /// A version number is not a valid ABI version (major version zero is reserved/invalid).
    InvalidVersion {
        /// Major version that failed validation.
        major: u16,
        /// Minor version that failed validation.
        minor: u16,
    },
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostMajorNewer {
                host_major,
                plugin_major,
            } => write!(
                f,
                "ABI major version mismatch: host implements {host_major}.x but the plugin targets \
                 {plugin_major}.x (plugin is older than the host)"
            ),
            Self::PluginMajorNewer {
                host_major,
                plugin_major,
            } => write!(
                f,
                "ABI major version mismatch: plugin requires {plugin_major}.x but the host \
                 implements {host_major}.x (plugin is newer than the host)"
            ),
            Self::PluginMinorNewer {
                host_minor,
                plugin_minor,
            } => write!(
                f,
                "ABI minor version mismatch: plugin requires 1.{plugin_minor} but the host \
                 implements 1.{host_minor} (minor versions are additive; upgrade the host)"
            ),
            Self::InvalidVersion { major, minor } => {
                write!(
                    f,
                    "invalid ABI version {major}.{minor}: major version 0 is reserved"
                )
            }
        }
    }
}

impl std::error::Error for NegotiationError {}

/// Capability negotiation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// The plugin requested a capability code this ABI version does not define. Unknown codes are
    /// rejected rather than ignored so a plugin built for a newer minor version fails loudly.
    Unsupported {
        /// Raw capability code requested by the plugin.
        code: u32,
    },
    /// The capability is defined by this ABI version but the host policy does not grant it.
    NotGranted {
        /// Capability that was requested but not granted.
        capability: Capability,
    },
    /// The plugin requested the same capability more than once.
    Duplicate {
        /// Raw capability code that was repeated.
        code: u32,
    },
    /// The plugin requested more capabilities than a descriptor may contain.
    TooMany {
        /// Number of requested capabilities.
        count: usize,
        /// Maximum accepted by this ABI version.
        max: usize,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { code } => write!(
                f,
                "unsupported capability code {code}: this ABI version defines capabilities 1..=5"
            ),
            Self::NotGranted { capability } => write!(
                f,
                "capability `{}` (code {}) is not granted by the host policy",
                capability.name(),
                capability.code()
            ),
            Self::Duplicate { code } => {
                write!(f, "capability code {code} is requested more than once")
            }
            Self::TooMany { count, max } => {
                write!(
                    f,
                    "{count} requested capabilities exceed the maximum of {max}"
                )
            }
        }
    }
}

impl std::error::Error for CapabilityError {}

/// A plugin descriptor is structurally malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    /// The plugin name is empty.
    EmptyName,
    /// The plugin name is longer than [`crate::descriptor::MAX_PLUGIN_NAME_LEN`].
    NameTooLong {
        /// Observed name length in bytes.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// The plugin name contains a character outside `[A-Za-z0-9._-]`.
    InvalidNameCharacter {
        /// Offending character.
        character: char,
    },
    /// The descriptor's ABI version is invalid (major version zero).
    InvalidAbiVersion {
        /// Major version.
        major: u16,
        /// Minor version.
        minor: u16,
    },
    /// A limit has a zero value; every limit must be a positive bound.
    ZeroLimit {
        /// Field name (`limits.max_request_body_bytes`, ...).
        field: &'static str,
    },
    /// A limit exceeds the hard cap this ABI version allows.
    LimitTooLarge {
        /// Field name.
        field: &'static str,
        /// Requested limit.
        value: u64,
        /// Hard cap for the field.
        max: u64,
    },
    /// The descriptor lists more capabilities than [`crate::capability::MAX_REQUESTED_CAPABILITIES`].
    TooManyCapabilities {
        /// Number of requested capabilities.
        count: usize,
        /// Maximum accepted count.
        max: usize,
    },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "plugin descriptor name must not be empty"),
            Self::NameTooLong { len, max } => {
                write!(f, "plugin descriptor name is {len} bytes, maximum is {max}")
            }
            Self::InvalidNameCharacter { character } => write!(
                f,
                "plugin descriptor name contains invalid character {character:?}; allowed are \
                 ASCII letters, digits, '.', '_' and '-'"
            ),
            Self::InvalidAbiVersion { major, minor } => {
                write!(
                    f,
                    "plugin descriptor ABI version {major}.{minor} is invalid"
                )
            }
            Self::ZeroLimit { field } => write!(f, "plugin descriptor {field} must be positive"),
            Self::LimitTooLarge { field, value, max } => write!(
                f,
                "plugin descriptor {field} is {value}, which exceeds the ABI hard cap {max}"
            ),
            Self::TooManyCapabilities { count, max } => write!(
                f,
                "plugin descriptor requests {count} capabilities, maximum is {max}"
            ),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// A host call was refused or could not be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCallError {
    /// The call was made by a plugin instance from an older configuration generation. Host calls
    /// are generation-scoped: after a reload the old instance is stale and must be dropped.
    StaleGeneration {
        /// Generation the plugin instance was loaded from.
        call_generation: u64,
        /// Generation that is currently active.
        active_generation: u64,
    },
    /// The call requires a capability that was not granted to this plugin.
    CapabilityDenied {
        /// Capability the call requires.
        capability: Capability,
        /// Host-call code.
        call: u32,
    },
    /// The per-request host-call budget is exhausted.
    CallBudgetExhausted {
        /// Budget the plugin was granted.
        max: u32,
    },
    /// The call arguments are outside the ABI limits or otherwise invalid.
    InvalidArgument {
        /// Human-readable reason; not part of the stable contract.
        message: String,
    },
    /// The host cancelled the call (for example because the request was aborted).
    Cancelled,
    /// The host could not complete the call (for example the generation-scoped HTTP client
    /// failed); the plugin should surface a generic failure to the request handler.
    HostFailure {
        /// Human-readable reason; not part of the stable contract.
        message: String,
    },
}

impl fmt::Display for HostCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleGeneration {
                call_generation,
                active_generation,
            } => write!(
                f,
                "host call from stale plugin generation {call_generation}: active generation is \
                 {active_generation}"
            ),
            Self::CapabilityDenied { capability, call } => write!(
                f,
                "host call {call} requires capability `{}` (code {}), which was not granted",
                capability.name(),
                capability.code()
            ),
            Self::CallBudgetExhausted { max } => {
                write!(f, "host-call budget exhausted ({max} calls per request)")
            }
            Self::InvalidArgument { message } => write!(f, "invalid host-call argument: {message}"),
            Self::Cancelled => write!(f, "host call was cancelled"),
            Self::HostFailure { message } => write!(f, "host call failed: {message}"),
        }
    }
}

impl std::error::Error for HostCallError {}

/// A wire frame or payload could not be decoded (or could not be encoded within the ABI limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// More bytes were required than the input contains.
    UnexpectedEof {
        /// Byte offset where decoding ran out of input.
        offset: usize,
        /// Number of bytes the decoder needed.
        needed: usize,
        /// Number of bytes that were available.
        remaining: usize,
    },
    /// A frame's declared payload length exceeds the frame limit.
    FrameTooLarge {
        /// Declared payload length.
        len: usize,
        /// Maximum accepted payload length.
        max: usize,
    },
    /// A frame tag is not defined by this ABI version.
    UnknownFrameTag {
        /// Offending tag byte.
        tag: u8,
    },
    /// A host-call code is not defined by this ABI version.
    UnknownHostCallCode {
        /// Offending host-call code.
        code: u32,
    },
    /// A host-call result code does not match the request or is not defined.
    UnknownHostCallResult {
        /// Offending result code.
        code: u32,
    },
    /// An ABI error-code frame carries an undefined error code.
    UnknownAbiErrorCode {
        /// Offending error code.
        code: u32,
    },
    /// A log-level byte is not defined.
    UnknownLogLevel {
        /// Offending log-level byte.
        code: u8,
    },
    /// A method code is not defined by this ABI version.
    UnknownMethod {
        /// Offending method code.
        code: u8,
    },
    /// A body-mode tag is not defined by this ABI version.
    UnknownBodyMode {
        /// Offending body-mode tag.
        tag: u8,
    },
    /// A wire ABI version has major version zero, which is reserved/invalid.
    InvalidAbiVersion {
        /// Major version.
        major: u16,
        /// Minor version.
        minor: u16,
    },
    /// A string field is not valid UTF-8.
    InvalidUtf8 {
        /// Byte offset of the offending string.
        offset: usize,
    },
    /// A byte/string/header field exceeds the limit for its position.
    LimitExceeded {
        /// Field or frame component that exceeded the limit.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// A length or numeric field cannot be represented by the wire format.
    SizeOverflow {
        /// Field that overflowed.
        field: &'static str,
    },
    /// Bytes remain after decoding a complete frame or payload.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
    /// A header name contains a byte that is not a valid HTTP token character.
    InvalidHeaderName {
        /// Byte offset of the offending header name.
        offset: usize,
    },
    /// A response status is outside the valid HTTP range (100..=999).
    InvalidStatus {
        /// Offending status code.
        status: u16,
    },
    /// A frame was zero bytes long, so it cannot carry a tag.
    EmptyFrame,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected end of input at byte {offset}: needed {needed} bytes, {remaining} available"
            ),
            Self::FrameTooLarge { len, max } => {
                write!(f, "frame payload of {len} bytes exceeds the maximum of {max}")
            }
            Self::UnknownFrameTag { tag } => write!(f, "unknown bridge frame tag {tag}"),
            Self::UnknownHostCallCode { code } => write!(f, "unknown host-call code {code}"),
            Self::UnknownHostCallResult { code } => {
                write!(f, "unknown host-call result code {code}")
            }
            Self::UnknownAbiErrorCode { code } => write!(f, "unknown ABI error code {code}"),
            Self::UnknownLogLevel { code } => write!(f, "unknown log level code {code}"),
            Self::UnknownMethod { code } => write!(f, "unknown HTTP method code {code}"),
            Self::UnknownBodyMode { tag } => write!(f, "unknown body-mode tag {tag}"),
            Self::InvalidAbiVersion { major, minor } => {
                write!(f, "invalid ABI version {major}.{minor} on the wire")
            }
            Self::InvalidUtf8 { offset } => {
                write!(f, "string at byte {offset} is not valid UTF-8")
            }
            Self::LimitExceeded { field, len, max } => {
                write!(f, "{field} is {len} bytes, maximum is {max}")
            }
            Self::SizeOverflow { field } => {
                write!(f, "{field} is too large for the wire encoding")
            }
            Self::TrailingBytes { count } => {
                write!(f, "{count} trailing byte(s) after a complete frame or payload")
            }
            Self::InvalidHeaderName { offset } => write!(
                f,
                "header name at byte {offset} contains a byte that is not a valid HTTP token character"
            ),
            Self::InvalidStatus { status } => {
                write!(f, "HTTP status {status} is outside the valid range 100..=999")
            }
            Self::EmptyFrame => write!(f, "empty frame: a bridge frame needs at least a tag byte"),
        }
    }
}

impl std::error::Error for WireError {}

/// Any ABI-contract error, for callers that want one error type across the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    /// Version negotiation failed.
    Negotiation(NegotiationError),
    /// Capability negotiation failed.
    Capability(CapabilityError),
    /// The descriptor is malformed.
    Descriptor(DescriptorError),
    /// A host call was refused or failed.
    HostCall(HostCallError),
    /// A wire frame or payload is malformed.
    Wire(WireError),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negotiation(error) => write!(f, "{error}"),
            Self::Capability(error) => write!(f, "{error}"),
            Self::Descriptor(error) => write!(f, "{error}"),
            Self::HostCall(error) => write!(f, "{error}"),
            Self::Wire(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AbiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Negotiation(error) => Some(error),
            Self::Capability(error) => Some(error),
            Self::Descriptor(error) => Some(error),
            Self::HostCall(error) => Some(error),
            Self::Wire(error) => Some(error),
        }
    }
}

impl From<NegotiationError> for AbiError {
    fn from(error: NegotiationError) -> Self {
        Self::Negotiation(error)
    }
}

impl From<CapabilityError> for AbiError {
    fn from(error: CapabilityError) -> Self {
        Self::Capability(error)
    }
}

impl From<DescriptorError> for AbiError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl From<HostCallError> for AbiError {
    fn from(error: HostCallError) -> Self {
        Self::HostCall(error)
    }
}

impl From<WireError> for AbiError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

/// Stable error codes the host sends to a plugin in an ABI error frame.
///
/// These values are part of the ABI: they may be appended in a minor version but never renumbered.
/// The host may surface a plugin's error to the HTTP client, so these are deliberately coarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum AbiErrorCode {
    /// A host call required a capability the plugin was not granted.
    CapabilityDenied = 1000,
    /// The plugin instance belongs to a stale configuration generation.
    StaleGeneration = 1001,
    /// A body/header/frame/call limit was exceeded.
    LimitExceeded = 1002,
    /// The plugin sent an invalid request to the host.
    InvalidRequest = 1003,
    /// The host failed while performing a host call.
    HostFailure = 1004,
    /// The request was cancelled by the client or the host.
    Cancelled = 1005,
    /// The plugin used a feature this ABI version does not support.
    Unsupported = 1006,
    /// The plugin trapped, panicked or violated the ABI.
    PluginFailed = 1007,
}

impl AbiErrorCode {
    /// Numeric code used on the wire.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Decode a wire code, rejecting undefined values.
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1000 => Some(Self::CapabilityDenied),
            1001 => Some(Self::StaleGeneration),
            1002 => Some(Self::LimitExceeded),
            1003 => Some(Self::InvalidRequest),
            1004 => Some(Self::HostFailure),
            1005 => Some(Self::Cancelled),
            1006 => Some(Self::Unsupported),
            1007 => Some(Self::PluginFailed),
            _ => None,
        }
    }
}
