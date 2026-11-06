//! Host calls, their capability requirements and generation-scoped authorisation.
//!
//! A plugin never performs I/O directly. It sends a [`HostCall`] frame; the host validates it in a
//! [`HostCallContext`] and answers with a [`HostCallResult`] (or an
//! [`crate::bridge::AbiErrorFrame`] for failures).
//!
//! # Host-call codes (stable ABI)
//!
//! | Code | Call | Required capability | Result |
//! |------|------|---------------------|--------|
//! | 1 | [`HostCall::Log`] | [`Capability::Log`] | [`HostCallResult::Logged`] |
//! | 2 | [`HostCall::Now`] | [`Capability::Clock`] | [`HostCallResult::Now`] |
//! | 3 | [`HostCall::Random`] | [`Capability::Random`] | [`HostCallResult::Random`] |
//! | 4 | [`HostCall::HttpRequest`] | [`Capability::HttpClient`] | [`HostCallResult::HttpResponse`] |
//! | 5 | [`HostCall::ReadConfig`] | [`Capability::ConfigRead`] | [`HostCallResult::ConfigValue`] |
//!
//! # Generation scope
//!
//! Every plugin instance is created for one configuration generation. Host calls are only legal
//! while that generation is active: after a reload the old instance is stale and calls fail with
//! [`HostCallError::StaleGeneration`] instead of observing state from two configurations. HTTP
//! requests issued through `HttpRequest` and configuration snapshots read through `ReadConfig` are
//! scoped to the same generation and are immutable for its lifetime.
//!
//! # Budget and limits
//!
//! Each request has a host-call budget from the negotiated
//! [`crate::descriptor::PluginLimits::max_host_calls_per_request`]; arguments are checked against
//! the ABI limits before the budget is consumed. This module enforces authorisation and argument
//! limits only; actual I/O is implemented by the runtime (T-PLUG-011).

use serde::{Deserialize, Serialize};

use crate::bridge::{is_http_token_byte, AbiLimits, BridgeHeaders, BridgeMethod};
use crate::capability::{Capability, CapabilitySet};
use crate::encoding::{Reader, Writer};
use crate::error::{HostCallError, WireError};

/// Host-call code for [`HostCall::Log`].
pub const HOST_CALL_LOG: u32 = 1;
/// Host-call code for [`HostCall::Now`].
pub const HOST_CALL_NOW: u32 = 2;
/// Host-call code for [`HostCall::Random`].
pub const HOST_CALL_RANDOM: u32 = 3;
/// Host-call code for [`HostCall::HttpRequest`].
pub const HOST_CALL_HTTP_REQUEST: u32 = 4;
/// Host-call code for [`HostCall::ReadConfig`].
pub const HOST_CALL_READ_CONFIG: u32 = 5;

/// Maximum number of key/value fields in one log record.
pub const MAX_LOG_FIELDS: usize = 32;
/// Maximum log message length.
pub const MAX_LOG_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum log field name length.
pub const MAX_LOG_FIELD_NAME_BYTES: usize = 64;
/// Maximum log field value length.
pub const MAX_LOG_FIELD_VALUE_BYTES: usize = 1024;
/// Maximum random bytes returned by one host call.
pub const MAX_RANDOM_BYTES: u32 = 64;
/// Maximum outbound HTTP URL length.
pub const MAX_URL_BYTES: usize = 8 * 1024;
/// Maximum body length of an outbound host-call HTTP request or response.
pub const MAX_HOST_CALL_BODY_BYTES: usize = 1024 * 1024;
/// Maximum configuration key length for [`HostCall::ReadConfig`].
pub const MAX_CONFIG_KEY_BYTES: usize = 256;

/// Maximum configuration value length returned by [`HostCall::ReadConfig`].
pub const MAX_CONFIG_VALUE_BYTES: usize = 64 * 1024;

/// Log severity used by [`HostCall::Log`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LogLevel {
    /// Debug-level diagnostic.
    Debug = 0,
    /// Informational message.
    Info = 1,
    /// Warning.
    Warn = 2,
    /// Error.
    Error = 3,
}

impl LogLevel {
    /// Stable wire code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode a wire code, rejecting undefined levels.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Debug),
            1 => Some(Self::Info),
            2 => Some(Self::Warn),
            3 => Some(Self::Error),
            _ => None,
        }
    }

    /// Stable name used in host logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// A call from the plugin into the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostCall {
    /// Emit a structured log record.
    Log {
        /// Severity.
        level: LogLevel,
        /// Message text.
        message: String,
        /// Structured key/value fields.
        fields: Vec<(String, String)>,
    },
    /// Read the host clock. Time is not a capability by accident: without [`Capability::Clock`] the
    /// plugin cannot observe wall time.
    Now,
    /// Ask the host for cryptographically secure random bytes.
    Random {
        /// Number of bytes requested (at most [`MAX_RANDOM_BYTES`]).
        len: u32,
    },
    /// Perform an outbound HTTP request through the host. Only available with
    /// [`Capability::HttpClient`]; requests are generation-scoped and subject to host policy.
    HttpRequest {
        /// Request method.
        method: BridgeMethod,
        /// Absolute URL (`http`/`https`).
        url: String,
        /// Request headers.
        headers: BridgeHeaders,
        /// Request body (buffered; host-call HTTP is not streamed in ABI v1).
        body: Vec<u8>,
    },
    /// Read a value from the immutable configuration snapshot of the current generation.
    ReadConfig {
        /// Configuration key (placeholder-style or JSON pointer, host-defined; at most
        /// [`MAX_CONFIG_KEY_BYTES`]).
        key: String,
    },
}

impl HostCall {
    /// Stable host-call code.
    pub const fn code(&self) -> u32 {
        match self {
            Self::Log { .. } => HOST_CALL_LOG,
            Self::Now => HOST_CALL_NOW,
            Self::Random { .. } => HOST_CALL_RANDOM,
            Self::HttpRequest { .. } => HOST_CALL_HTTP_REQUEST,
            Self::ReadConfig { .. } => HOST_CALL_READ_CONFIG,
        }
    }

    /// Capability required to perform this call.
    pub const fn required_capability(&self) -> Capability {
        match self {
            Self::Log { .. } => Capability::Log,
            Self::Now => Capability::Clock,
            Self::Random { .. } => Capability::Random,
            Self::HttpRequest { .. } => Capability::HttpClient,
            Self::ReadConfig { .. } => Capability::ConfigRead,
        }
    }

    /// Validate call arguments against the ABI limits, independent of capabilities.
    pub fn validate(&self, limits: &AbiLimits) -> Result<(), HostCallError> {
        match self {
            Self::Log {
                message, fields, ..
            } => {
                if message.len() > limits.max_log_message {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "log message is {} bytes, maximum is {}",
                            message.len(),
                            limits.max_log_message
                        ),
                    });
                }
                if fields.len() > limits.max_log_fields {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "log record has {} fields, maximum is {}",
                            fields.len(),
                            limits.max_log_fields
                        ),
                    });
                }
                for (name, value) in fields {
                    if name.len() > MAX_LOG_FIELD_NAME_BYTES
                        || !name.bytes().all(is_http_token_byte)
                    {
                        return Err(HostCallError::InvalidArgument {
                            message: format!("invalid log field name `{name}`"),
                        });
                    }
                    if value.len() > MAX_LOG_FIELD_VALUE_BYTES {
                        return Err(HostCallError::InvalidArgument {
                            message: format!(
                                "log field `{name}` value is {} bytes, maximum is {}",
                                value.len(),
                                MAX_LOG_FIELD_VALUE_BYTES
                            ),
                        });
                    }
                }
                Ok(())
            }
            Self::Now => Ok(()),
            Self::Random { len } => {
                if *len > limits.max_random_bytes {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "requested {len} random bytes, maximum is {}",
                            limits.max_random_bytes
                        ),
                    });
                }
                Ok(())
            }
            Self::HttpRequest {
                method,
                url,
                headers,
                body,
            } => {
                if url.len() > limits.max_url {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "outbound URL is {} bytes, maximum is {}",
                            url.len(),
                            limits.max_url
                        ),
                    });
                }
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(HostCallError::InvalidArgument {
                        message: "outbound URL must be absolute http(s)".to_string(),
                    });
                }
                if method.as_str().is_empty() {
                    return Err(HostCallError::InvalidArgument {
                        message: "outbound HTTP method must not be empty".to_string(),
                    });
                }
                if headers.len() > limits.max_header_count {
                    return Err(HostCallError::InvalidArgument {
                        message: "outbound request has too many headers".to_string(),
                    });
                }
                if body.len() > limits.max_host_call_body {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "outbound request body is {} bytes, maximum is {}",
                            body.len(),
                            limits.max_host_call_body
                        ),
                    });
                }
                Ok(())
            }
            Self::ReadConfig { key } => {
                if key.is_empty() {
                    return Err(HostCallError::InvalidArgument {
                        message: "config key must not be empty".to_string(),
                    });
                }
                if key.len() > limits.max_config_key {
                    return Err(HostCallError::InvalidArgument {
                        message: format!(
                            "config key is {} bytes, maximum is {}",
                            key.len(),
                            limits.max_config_key
                        ),
                    });
                }
                Ok(())
            }
        }
    }

    /// Encode a complete host-call payload (call code plus arguments).
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        writer.u32(self.code());
        match self {
            Self::Log {
                level,
                message,
                fields,
            } => {
                writer.u8(level.code());
                writer.string("log message", message)?;
                writer.u16(
                    u16::try_from(fields.len()).map_err(|_| WireError::SizeOverflow {
                        field: "log field count",
                    })?,
                );
                for (name, value) in fields {
                    writer.string("log field name", name)?;
                    writer.string("log field value", value)?;
                }
            }
            Self::Now => {}
            Self::Random { len } => writer.u32(*len),
            Self::HttpRequest {
                method,
                url,
                headers,
                body,
            } => {
                method.encode(writer, limits)?;
                writer.string("url", url)?;
                headers.encode(writer, limits)?;
                writer.bytes("host-call body", body)?;
            }
            Self::ReadConfig { key } => writer.string("config key", key)?,
        }
        Ok(())
    }

    /// Decode a complete host-call payload.
    ///
    /// Wire-level limits (string/header/body sizes) are enforced here. The host must still call
    /// [`HostCall::validate`] before executing the call: that is where semantic argument rules
    /// (absolute http(s) URL, request length bounds) and their typed error live.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let code = reader.u32()?;
        let call = match code {
            HOST_CALL_LOG => {
                let level_code = reader.u8()?;
                let level = LogLevel::from_code(level_code)
                    .ok_or(WireError::UnknownLogLevel { code: level_code })?;
                let message = reader.string("log message", limits.max_log_message)?;
                let field_count = reader.u16()? as usize;
                if field_count > limits.max_log_fields {
                    return Err(WireError::LimitExceeded {
                        field: "log field count",
                        len: field_count,
                        max: limits.max_log_fields,
                    });
                }
                let mut fields = Vec::with_capacity(field_count);
                for _ in 0..field_count {
                    let name = reader.string("log field name", MAX_LOG_FIELD_NAME_BYTES)?;
                    if !name.bytes().all(is_http_token_byte) {
                        return Err(WireError::InvalidHeaderName {
                            offset: reader.position(),
                        });
                    }
                    let value = reader.string("log field value", MAX_LOG_FIELD_VALUE_BYTES)?;
                    fields.push((name, value));
                }
                Self::Log {
                    level,
                    message,
                    fields,
                }
            }
            HOST_CALL_NOW => Self::Now,
            HOST_CALL_RANDOM => Self::Random { len: reader.u32()? },
            HOST_CALL_HTTP_REQUEST => {
                let method = BridgeMethod::decode(reader, limits)?;
                let url = reader.string("url", limits.max_url)?;
                let headers = BridgeHeaders::decode(reader, limits)?;
                let body = reader
                    .bytes("host-call body", limits.max_host_call_body)?
                    .to_vec();
                Self::HttpRequest {
                    method,
                    url,
                    headers,
                    body,
                }
            }
            HOST_CALL_READ_CONFIG => Self::ReadConfig {
                key: reader.string("config key", limits.max_config_key)?,
            },
            other => return Err(WireError::UnknownHostCallCode { code: other }),
        };
        Ok(call)
    }
}

/// Result of a successful host call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostCallResult {
    /// Acknowledgement of [`HostCall::Log`].
    Logged,
    /// Result of [`HostCall::Now`]: nanoseconds since the Unix epoch.
    Now {
        /// Unix timestamp in nanoseconds.
        unix_nanos: u64,
    },
    /// Result of [`HostCall::Random`].
    Random {
        /// Requested random bytes (length equals the request length).
        bytes: Vec<u8>,
    },
    /// Result of [`HostCall::HttpRequest`].
    HttpResponse {
        /// Response status.
        status: u16,
        /// Response headers.
        headers: BridgeHeaders,
        /// Buffered response body.
        body: Vec<u8>,
    },
    /// Result of [`HostCall::ReadConfig`].
    ConfigValue {
        /// Configuration value, or `None` when the key does not exist in this generation.
        value: Option<String>,
    },
}

impl HostCallResult {
    /// Stable result code, matching the host-call code it answers.
    pub const fn code(&self) -> u32 {
        match self {
            Self::Logged => HOST_CALL_LOG,
            Self::Now { .. } => HOST_CALL_NOW,
            Self::Random { .. } => HOST_CALL_RANDOM,
            Self::HttpResponse { .. } => HOST_CALL_HTTP_REQUEST,
            Self::ConfigValue { .. } => HOST_CALL_READ_CONFIG,
        }
    }

    /// Encode the result payload (call code plus result data).
    pub fn encode(&self, writer: &mut Writer, limits: &AbiLimits) -> Result<(), WireError> {
        writer.u32(self.code());
        match self {
            Self::Logged => {}
            Self::Now { unix_nanos } => writer.u64(*unix_nanos),
            Self::Random { bytes } => {
                if bytes.len() > MAX_RANDOM_BYTES as usize {
                    return Err(WireError::LimitExceeded {
                        field: "random bytes",
                        len: bytes.len(),
                        max: MAX_RANDOM_BYTES as usize,
                    });
                }
                writer.bytes("random bytes", bytes)?;
            }
            Self::HttpResponse {
                status,
                headers,
                body,
            } => {
                if !(100..=999).contains(status) {
                    return Err(WireError::InvalidStatus { status: *status });
                }
                if body.len() > limits.max_host_call_body {
                    return Err(WireError::LimitExceeded {
                        field: "host-call body",
                        len: body.len(),
                        max: limits.max_host_call_body,
                    });
                }
                writer.u16(*status);
                headers.encode(writer, limits)?;
                writer.bytes("host-call body", body)?;
            }
            Self::ConfigValue { value } => match value {
                Some(value) => {
                    if value.len() > MAX_CONFIG_VALUE_BYTES {
                        return Err(WireError::LimitExceeded {
                            field: "config value",
                            len: value.len(),
                            max: MAX_CONFIG_VALUE_BYTES,
                        });
                    }
                    writer.u8(1);
                    writer.string("config value", value)?;
                }
                None => writer.u8(0),
            },
        }
        Ok(())
    }

    /// Decode a result payload, rejecting unknown/mismatched result codes.
    pub fn decode(reader: &mut Reader<'_>, limits: &AbiLimits) -> Result<Self, WireError> {
        let code = reader.u32()?;
        let result = match code {
            HOST_CALL_LOG => Self::Logged,
            HOST_CALL_NOW => Self::Now {
                unix_nanos: reader.u64()?,
            },
            HOST_CALL_RANDOM => Self::Random {
                bytes: reader
                    .bytes("random bytes", MAX_RANDOM_BYTES as usize)?
                    .to_vec(),
            },
            HOST_CALL_HTTP_REQUEST => {
                let status = reader.u16()?;
                if !(100..=999).contains(&status) {
                    return Err(WireError::InvalidStatus { status });
                }
                let headers = BridgeHeaders::decode(reader, limits)?;
                let body = reader
                    .bytes("host-call body", limits.max_host_call_body)?
                    .to_vec();
                Self::HttpResponse {
                    status,
                    headers,
                    body,
                }
            }
            HOST_CALL_READ_CONFIG => {
                let present = reader.u8()?;
                let value = match present {
                    0 => None,
                    1 => Some(reader.string("config value", MAX_CONFIG_VALUE_BYTES)?),
                    other => {
                        return Err(WireError::UnknownHostCallResult {
                            code: u32::from(other),
                        })
                    }
                };
                Self::ConfigValue { value }
            }
            other => return Err(WireError::UnknownHostCallResult { code: other }),
        };
        Ok(result)
    }
}

/// Per-request host-call authorisation and budget state.
///
/// The host creates one context per request (or per plugin invocation) with the negotiated
/// generation and capability set, calls [`HostCallContext::authorize`] for each
/// [`HostCall`] frame, and performs the call only if it returns `Ok`.
#[derive(Debug, Clone)]
pub struct HostCallContext {
    generation: u64,
    granted: CapabilitySet,
    budget: u32,
    remaining: u32,
}

impl HostCallContext {
    /// Create a context for `generation` with the granted capabilities and per-request budget.
    pub fn new(generation: u64, granted: CapabilitySet, budget: u32) -> Self {
        Self {
            generation,
            granted,
            budget,
            remaining: budget,
        }
    }

    /// Generation this plugin instance belongs to.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Granted capabilities.
    pub const fn granted(&self) -> CapabilitySet {
        self.granted
    }

    /// Remaining host calls in this request.
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Authorise one host call against generation, capabilities, argument limits and budget.
    ///
    /// Checks run in this order and the budget is consumed only when the call is authorised:
    ///
    /// 1. the context generation must equal `active_generation`
    ///    ([`HostCallError::StaleGeneration`]);
    /// 2. the call's required capability must be granted
    ///    ([`HostCallError::CapabilityDenied`]);
    /// 3. arguments must satisfy the ABI limits ([`HostCallError::InvalidArgument`]);
    /// 4. the per-request budget must not be exhausted ([`HostCallError::CallBudgetExhausted`]).
    pub fn authorize(
        &mut self,
        call: &HostCall,
        active_generation: u64,
        limits: &AbiLimits,
    ) -> Result<(), HostCallError> {
        if self.generation != active_generation {
            return Err(HostCallError::StaleGeneration {
                call_generation: self.generation,
                active_generation,
            });
        }
        let required = call.required_capability();
        if !self.granted.contains(required) {
            return Err(HostCallError::CapabilityDenied {
                capability: required,
                call: call.code(),
            });
        }
        call.validate(limits)?;
        if self.remaining == 0 {
            return Err(HostCallError::CallBudgetExhausted { max: self.budget });
        }
        self.remaining -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> AbiLimits {
        AbiLimits::spec_defaults()
    }

    #[test]
    fn host_call_codes_are_stable() {
        assert_eq!(HOST_CALL_LOG, 1);
        assert_eq!(HOST_CALL_NOW, 2);
        assert_eq!(HOST_CALL_RANDOM, 3);
        assert_eq!(HOST_CALL_HTTP_REQUEST, 4);
        assert_eq!(HOST_CALL_READ_CONFIG, 5);
        assert_eq!(HostCall::Now.required_capability(), Capability::Clock);
        assert_eq!(
            HostCall::ReadConfig {
                key: "k".to_string()
            }
            .required_capability(),
            Capability::ConfigRead
        );
    }

    #[test]
    fn calls_and_results_round_trip() {
        let limits = limits();
        let calls = vec![
            HostCall::Log {
                level: LogLevel::Warn,
                message: "hello".to_string(),
                fields: vec![("k".to_string(), "v".to_string())],
            },
            HostCall::Now,
            HostCall::Random { len: 8 },
            HostCall::HttpRequest {
                method: BridgeMethod::Post,
                url: "https://example.com/x".to_string(),
                headers: BridgeHeaders::new([("accept".to_string(), "*/*".to_string())])
                    .expect("headers"),
                body: b"payload".to_vec(),
            },
            HostCall::ReadConfig {
                key: "site.root".to_string(),
            },
        ];
        for call in calls {
            let mut writer = Writer::new();
            call.encode(&mut writer, &limits).expect("encode call");
            let encoded = writer.into_vec();
            let mut reader = Reader::new(&encoded);
            assert_eq!(
                HostCall::decode(&mut reader, &limits).expect("decode call"),
                call
            );
            reader.finish().expect("fully consumed");
        }
        let results = vec![
            HostCallResult::Logged,
            HostCallResult::Now { unix_nanos: 42 },
            HostCallResult::Random { bytes: vec![1, 2] },
            HostCallResult::HttpResponse {
                status: 200,
                headers: BridgeHeaders::default(),
                body: b"ok".to_vec(),
            },
            HostCallResult::ConfigValue {
                value: Some("root".to_string()),
            },
            HostCallResult::ConfigValue { value: None },
        ];
        for result in results {
            let mut writer = Writer::new();
            result.encode(&mut writer, &limits).expect("encode result");
            let encoded = writer.into_vec();
            let mut reader = Reader::new(&encoded);
            assert_eq!(
                HostCallResult::decode(&mut reader, &limits).expect("decode result"),
                result
            );
            reader.finish().expect("fully consumed");
        }
    }

    #[test]
    fn unknown_codes_and_bad_arguments_are_rejected() {
        let limits = limits();
        let mut reader = Reader::new(&[99, 0, 0, 0]);
        assert_eq!(
            HostCall::decode(&mut reader, &limits),
            Err(WireError::UnknownHostCallCode { code: 99 })
        );
        let mut reader = Reader::new(&[99, 0, 0, 0]);
        assert_eq!(
            HostCallResult::decode(&mut reader, &limits),
            Err(WireError::UnknownHostCallResult { code: 99 })
        );
        assert!(matches!(
            HostCall::Random {
                len: MAX_RANDOM_BYTES + 1
            }
            .validate(&limits),
            Err(HostCallError::InvalidArgument { .. })
        ));
        assert!(matches!(
            HostCall::ReadConfig { key: String::new() }.validate(&limits),
            Err(HostCallError::InvalidArgument { .. })
        ));
        assert!(matches!(
            HostCall::HttpRequest {
                method: BridgeMethod::Get,
                url: "ftp://example.com".to_string(),
                headers: BridgeHeaders::default(),
                body: Vec::new(),
            }
            .validate(&limits),
            Err(HostCallError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn authorization_checks_generation_capability_budget_and_arguments() {
        let limits = limits();
        let granted = CapabilitySet::from_capabilities([Capability::Clock, Capability::Log]);
        let mut context = HostCallContext::new(7, granted, 2);

        // Stale generation is checked first, even for a granted call.
        assert_eq!(
            context.authorize(&HostCall::Now, 8, &limits),
            Err(HostCallError::StaleGeneration {
                call_generation: 7,
                active_generation: 8
            })
        );
        // Capability not granted.
        assert_eq!(
            context.authorize(&HostCall::Random { len: 1 }, 7, &limits),
            Err(HostCallError::CapabilityDenied {
                capability: Capability::Random,
                call: HOST_CALL_RANDOM
            })
        );
        // Argument validation does not consume budget.
        assert!(matches!(
            context.authorize(
                &HostCall::Log {
                    level: LogLevel::Info,
                    message: "x".repeat(MAX_LOG_MESSAGE_BYTES + 1),
                    fields: Vec::new()
                },
                7,
                &limits
            ),
            Err(HostCallError::InvalidArgument { .. })
        ));
        assert_eq!(context.remaining(), 2);
        // Two granted calls consume the budget, the third fails.
        context
            .authorize(&HostCall::Now, 7, &limits)
            .expect("first");
        context
            .authorize(&HostCall::Now, 7, &limits)
            .expect("second");
        assert_eq!(context.remaining(), 0);
        assert!(matches!(
            context.authorize(&HostCall::Now, 7, &limits),
            Err(HostCallError::CallBudgetExhausted { .. })
        ));
    }
}
