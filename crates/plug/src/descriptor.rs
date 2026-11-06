//! Plugin descriptors and negotiated plugins.
//!
//! A plugin ships a descriptor with its name, target ABI version, requested capability codes and
//! mandatory resource limits. The descriptor is untrusted input: the host validates it
//! structurally ([`PluginDescriptor::validate`]), negotiates the ABI version and grants
//! capabilities ([`PluginDescriptor::negotiate`]) before instantiating any WASM code.
//!
//! Descriptors are plain data and derive `serde` traits so the host can load them from whatever
//! manifest format it chooses; this crate defines no manifest format of its own. The ABI contract
//! is the validated shape and the negotiation rules, not the file syntax.

use serde::{Deserialize, Serialize};

use crate::capability::{
    grant_capabilities, CapabilityPolicy, CapabilitySet, MAX_REQUESTED_CAPABILITIES,
};
use crate::error::{AbiError, DescriptorError};
use crate::version::{negotiate, AbiVersion, NegotiatedAbi};

/// Maximum plugin name length in bytes.
pub const MAX_PLUGIN_NAME_LEN: usize = 64;

/// Hard cap for a descriptor's request-body limit (64 MiB).
pub const HARD_MAX_REQUEST_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap for a descriptor's response-body limit (64 MiB).
pub const HARD_MAX_RESPONSE_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap for a descriptor's host-calls-per-request limit.
pub const HARD_MAX_HOST_CALLS_PER_REQUEST: u32 = 100_000;

/// Hard cap for a descriptor's linear-memory limit (512 MiB).
pub const HARD_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Resource limits a plugin requests. Every limit must be positive and within the ABI hard caps;
/// the host may enforce tighter bounds but must never exceed these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLimits {
    /// Maximum request body the plugin will be given, in bytes.
    pub max_request_body_bytes: u64,
    /// Maximum response body the plugin may produce, in bytes.
    pub max_response_body_bytes: u64,
    /// Maximum host calls permitted during one request.
    pub max_host_calls_per_request: u32,
    /// Maximum WASM linear memory the plugin may allocate, in bytes.
    pub max_memory_bytes: u64,
}

impl PluginLimits {
    /// Conservative defaults for a small middleware plugin: 1 MiB bodies, 1,000 host calls and
    /// 64 MiB of memory.
    pub const fn default_limits() -> Self {
        Self {
            max_request_body_bytes: 1024 * 1024,
            max_response_body_bytes: 1024 * 1024,
            max_host_calls_per_request: 1_000,
            max_memory_bytes: 64 * 1024 * 1024,
        }
    }

    /// Validate every limit against the ABI hard caps.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        for (field, value, hard_max) in [
            (
                "limits.max_request_body_bytes",
                self.max_request_body_bytes,
                HARD_MAX_REQUEST_BODY_BYTES,
            ),
            (
                "limits.max_response_body_bytes",
                self.max_response_body_bytes,
                HARD_MAX_RESPONSE_BODY_BYTES,
            ),
            (
                "limits.max_memory_bytes",
                self.max_memory_bytes,
                HARD_MAX_MEMORY_BYTES,
            ),
        ] {
            if value == 0 {
                return Err(DescriptorError::ZeroLimit { field });
            }
            if value > hard_max {
                return Err(DescriptorError::LimitTooLarge {
                    field,
                    value,
                    max: hard_max,
                });
            }
        }
        if self.max_host_calls_per_request == 0 {
            return Err(DescriptorError::ZeroLimit {
                field: "limits.max_host_calls_per_request",
            });
        }
        if self.max_host_calls_per_request > HARD_MAX_HOST_CALLS_PER_REQUEST {
            return Err(DescriptorError::LimitTooLarge {
                field: "limits.max_host_calls_per_request",
                value: u64::from(self.max_host_calls_per_request),
                max: u64::from(HARD_MAX_HOST_CALLS_PER_REQUEST),
            });
        }
        Ok(())
    }
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Untrusted plugin metadata the host validates and negotiates before loading WASM code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDescriptor {
    /// Stable plugin name (`[A-Za-z0-9._-]`, 1..=[`MAX_PLUGIN_NAME_LEN`] bytes).
    pub name: String,
    /// ABI version the plugin was built against.
    pub abi: AbiVersion,
    /// Raw capability codes the plugin requests. Codes are kept raw so unknown codes from a newer
    /// minor version are rejected loudly during negotiation instead of being silently dropped.
    pub capabilities: Vec<u32>,
    /// Resource limits the plugin requests.
    pub limits: PluginLimits,
}

impl PluginDescriptor {
    /// Validate the descriptor structurally.
    ///
    /// Checks the plugin name (non-empty, length, allowed characters), the ABI major version and
    /// the limits (positive, within the ABI hard caps) and the capability-count bound. Capability
    /// *codes* are validated during negotiation because that is where the host policy applies.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        if self.name.is_empty() {
            return Err(DescriptorError::EmptyName);
        }
        if self.name.len() > MAX_PLUGIN_NAME_LEN {
            return Err(DescriptorError::NameTooLong {
                len: self.name.len(),
                max: MAX_PLUGIN_NAME_LEN,
            });
        }
        for character in self.name.chars() {
            if !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')) {
                return Err(DescriptorError::InvalidNameCharacter { character });
            }
        }
        self.abi
            .validate()
            .map_err(|_| DescriptorError::InvalidAbiVersion {
                major: self.abi.major,
                minor: self.abi.minor,
            })?;
        self.limits.validate()?;
        if self.capabilities.len() > MAX_REQUESTED_CAPABILITIES {
            return Err(DescriptorError::TooManyCapabilities {
                count: self.capabilities.len(),
                max: MAX_REQUESTED_CAPABILITIES,
            });
        }
        Ok(())
    }

    /// Validate the descriptor, negotiate the ABI version against `host` and grant the requested
    /// capabilities against the operator `policy`.
    ///
    /// This is the single entry point a host runtime should call before instantiating a plugin: it
    /// produces the version the plugin may assume and the exact capability set it holds.
    pub fn negotiate(
        &self,
        host: AbiVersion,
        policy: &CapabilityPolicy,
    ) -> Result<NegotiatedPlugin, AbiError> {
        self.validate()?;
        let abi = negotiate(host, self.abi)?;
        let granted: CapabilitySet = grant_capabilities(&self.capabilities, policy)?;
        Ok(NegotiatedPlugin {
            name: self.name.clone(),
            abi,
            granted,
            limits: self.limits,
        })
    }
}

/// Result of validating and negotiating a [`PluginDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedPlugin {
    /// Validated plugin name.
    pub name: String,
    /// Negotiated ABI versions (plugin target and host).
    pub abi: NegotiatedAbi,
    /// Capabilities granted to this plugin instance.
    pub granted: CapabilitySet,
    /// Validated limits.
    pub limits: PluginLimits,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;

    fn descriptor() -> PluginDescriptor {
        PluginDescriptor {
            name: "example-plugin".to_string(),
            abi: AbiVersion::new(1, 0),
            capabilities: vec![1],
            limits: PluginLimits::default_limits(),
        }
    }

    #[test]
    fn valid_descriptor_negotiates() {
        let placeholder = PluginDescriptor {
            name: "example-plugin".to_string(),
            abi: AbiVersion::new(1, 0),
            capabilities: vec![1],
            limits: PluginLimits::default_limits(),
        };
        placeholder.validate().expect("valid");
        let policy = CapabilityPolicy::with_capabilities([Capability::Log]);
        let negotiated = placeholder
            .negotiate(AbiVersion::new(1, 0), &policy)
            .expect("negotiates");
        assert_eq!(negotiated.name, "example-plugin");
        assert_eq!(
            negotiated.granted,
            CapabilitySet::from_capabilities([Capability::Log])
        );
        assert_eq!(negotiated.limits, PluginLimits::default_limits());
    }

    #[test]
    fn malformed_descriptors_are_rejected() {
        let assert_error = |descriptor: PluginDescriptor, expected: DescriptorError| {
            assert_eq!(descriptor.validate(), Err(expected), "{descriptor:?}");
        };
        assert_error(
            PluginDescriptor {
                name: String::new(),
                ..descriptor()
            },
            DescriptorError::EmptyName,
        );
        assert_error(
            PluginDescriptor {
                name: "x".repeat(MAX_PLUGIN_NAME_LEN + 1),
                ..descriptor()
            },
            DescriptorError::NameTooLong {
                len: MAX_PLUGIN_NAME_LEN + 1,
                max: MAX_PLUGIN_NAME_LEN,
            },
        );
        assert_error(
            PluginDescriptor {
                name: "bad name".to_string(),
                ..descriptor()
            },
            DescriptorError::InvalidNameCharacter { character: ' ' },
        );
        assert_error(
            PluginDescriptor {
                abi: AbiVersion::new(0, 1),
                ..descriptor()
            },
            DescriptorError::InvalidAbiVersion { major: 0, minor: 1 },
        );
        assert_error(
            PluginDescriptor {
                limits: PluginLimits {
                    max_request_body_bytes: 0,
                    ..PluginLimits::default_limits()
                },
                ..descriptor()
            },
            DescriptorError::ZeroLimit {
                field: "limits.max_request_body_bytes",
            },
        );
        assert_error(
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
        );
        assert_error(
            PluginDescriptor {
                capabilities: vec![1; MAX_REQUESTED_CAPABILITIES + 1],
                ..descriptor()
            },
            DescriptorError::TooManyCapabilities {
                count: MAX_REQUESTED_CAPABILITIES + 1,
                max: MAX_REQUESTED_CAPABILITIES,
            },
        );
    }

    #[test]
    fn negotiation_failures_are_typed() {
        let policy = CapabilityPolicy::grant_all_v1();
        let outdated = PluginDescriptor {
            abi: AbiVersion::new(1, 0),
            ..descriptor()
        };
        assert!(matches!(
            outdated.negotiate(AbiVersion::new(2, 0), &policy),
            Err(AbiError::Negotiation(_))
        ));
        let newer = PluginDescriptor {
            abi: AbiVersion::new(2, 0),
            ..descriptor()
        };
        assert!(matches!(
            newer.negotiate(AbiVersion::new(1, 0), &policy),
            Err(AbiError::Negotiation(_))
        ));
        let unsupported = PluginDescriptor {
            capabilities: vec![99],
            ..descriptor()
        };
        assert!(matches!(
            unsupported.negotiate(AbiVersion::new(1, 0), &policy),
            Err(AbiError::Capability(_))
        ));
        let denied = PluginDescriptor {
            capabilities: vec![1],
            ..descriptor()
        };
        assert!(matches!(
            denied.negotiate(AbiVersion::new(1, 0), &CapabilityPolicy::deny_all()),
            Err(AbiError::Capability(_))
        ));
    }
}
