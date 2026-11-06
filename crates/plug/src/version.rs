//! ABI version numbers and negotiation.
//!
//! # Versioning policy
//!
//! The ABI uses `major.minor` versions with different compatibility rules:
//!
//! * **Major** versions are incompatible. A plugin and host must agree on the major version
//!   exactly; there is no attempt to emulate an older or newer major version. A host with a newer
//!   major version rejects older plugins (and vice versa) with a located error rather than loading
//!   them speculatively.
//! * **Minor** versions are additive. A plugin built for `1.N` works on every host that implements
//!   `1.M` with `M >= N`. The negotiation result records the plugin's target version (the features
//!   it may use); the host is allowed to be newer. A plugin that needs a newer minor than the host
//!   provides is rejected: loading it would silently drop features.
//! * Major version `0` is reserved and invalid on the wire.
//!
//! This module is pure data and functions: it performs no I/O and allocates nothing beyond the
//! fixed-size encoding helpers.

use serde::{Deserialize, Serialize};

use crate::encoding::{Reader, Writer};
use crate::error::{NegotiationError, WireError};

/// The ABI version defined by this crate.
pub const ABI_VERSION: AbiVersion = AbiVersion::new(1, 0);

/// Major version of [`ABI_VERSION`].
pub const ABI_MAJOR: u16 = ABI_VERSION.major;

/// Minor version of [`ABI_VERSION`].
pub const ABI_MINOR: u16 = ABI_VERSION.minor;

/// The version the caddy-rs plugin host advertises. Hosts that only differ in later additive
/// minor versions still negotiate successfully.
pub const HOST_ABI_VERSION: AbiVersion = ABI_VERSION;

/// A `major.minor` ABI version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AbiVersion {
    /// Incompatible-version axis; must be non-zero.
    pub major: u16,
    /// Additive-feature axis.
    pub minor: u16,
}

impl AbiVersion {
    /// Construct an ABI version.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// ABI 1.0, the version this crate defines.
    pub const ABI_1_0: Self = Self::new(1, 0);

    /// Validate that the version is representable on the ABI (major version must be non-zero).
    pub fn validate(self) -> Result<Self, NegotiationError> {
        if self.major == 0 {
            Err(NegotiationError::InvalidVersion {
                major: self.major,
                minor: self.minor,
            })
        } else {
            Ok(self)
        }
    }

    /// Encode as two little-endian `u16`s (4 bytes).
    pub fn encode(self, writer: &mut Writer) {
        writer.u16(self.major);
        writer.u16(self.minor);
    }

    /// Decode two little-endian `u16`s (4 bytes) and validate the version.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, WireError> {
        let major = reader.u16()?;
        let minor = reader.u16()?;
        let version = Self { major, minor };
        // The wire decoder validates the value; an invalid version is a protocol violation.
        version
            .validate()
            .map_err(|_| WireError::InvalidAbiVersion { major, minor })
    }
}

/// Result of a successful version negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedAbi {
    /// Version the plugin targets; the plugin may use every feature up to this minor version.
    pub plugin: AbiVersion,
    /// Version the host implements. May have a newer minor than [`Self::plugin`]; no newer major.
    pub host: AbiVersion,
}

impl NegotiatedAbi {
    /// Effective ABI version for the plugin's compiled feature set (its own target version).
    pub const fn effective(self) -> AbiVersion {
        self.plugin
    }
}

/// Negotiate the ABI version between a host and a plugin descriptor.
///
/// * identical `major.minor` versions are accepted;
/// * a host with the same major and an equal-or-newer minor accepts the plugin (additive minor
///   versions); the plugin keeps its own target version as the effective version;
/// * a different major version is rejected with [`NegotiationError::HostMajorNewer`] or
///   [`NegotiationError::PluginMajorNewer`];
/// * a plugin that needs a newer minor version than the host provides is rejected with
///   [`NegotiationError::PluginMinorNewer`];
/// * a major version of zero is rejected with [`NegotiationError::InvalidVersion`].
pub fn negotiate(host: AbiVersion, plugin: AbiVersion) -> Result<NegotiatedAbi, NegotiationError> {
    host.validate()?;
    plugin.validate()?;
    if plugin.major > host.major {
        return Err(NegotiationError::PluginMajorNewer {
            host_major: host.major,
            plugin_major: plugin.major,
        });
    }
    if plugin.major < host.major {
        return Err(NegotiationError::HostMajorNewer {
            host_major: host.major,
            plugin_major: plugin.major,
        });
    }
    if plugin.minor > host.minor {
        return Err(NegotiationError::PluginMinorNewer {
            host_minor: host.minor,
            plugin_minor: plugin.minor,
        });
    }
    Ok(NegotiatedAbi { plugin, host })
}

/// Encode an ABI version as 4 bytes.
pub fn encode_abi_version(version: AbiVersion) -> Vec<u8> {
    let mut writer = Writer::with_capacity(4);
    version.encode(&mut writer);
    writer.into_vec()
}

/// Decode an ABI version from exactly 4 bytes.
pub fn decode_abi_version(bytes: &[u8]) -> Result<AbiVersion, WireError> {
    let mut reader = Reader::new(bytes);
    let version = AbiVersion::decode(&mut reader)?;
    reader.finish()?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_constants_are_stable() {
        assert_eq!(ABI_MAJOR, 1);
        assert_eq!(ABI_MINOR, 0);
        assert_eq!(ABI_VERSION, AbiVersion::new(1, 0));
        assert_eq!(HOST_ABI_VERSION, ABI_VERSION);
    }

    #[test]
    fn version_encoding_is_four_little_endian_bytes() {
        let encoded = encode_abi_version(AbiVersion::new(1, 3));
        assert_eq!(encoded, vec![1, 0, 3, 0]);
        assert_eq!(
            decode_abi_version(&encoded).expect("decodes"),
            AbiVersion::new(1, 3)
        );
    }

    #[test]
    fn version_decoding_rejects_trailing_bytes_and_short_input() {
        assert_eq!(
            decode_abi_version(&[1, 0, 0]),
            Err(WireError::UnexpectedEof {
                offset: 2,
                needed: 2,
                remaining: 1
            })
        );
        assert_eq!(
            decode_abi_version(&[1, 0, 0, 0, 9]),
            Err(WireError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn exact_versions_negotiate() {
        let negotiated = negotiate(AbiVersion::new(1, 4), AbiVersion::new(1, 4)).expect("exact");
        assert_eq!(negotiated.plugin, AbiVersion::new(1, 4));
        assert_eq!(negotiated.host, AbiVersion::new(1, 4));
        assert_eq!(negotiated.effective(), AbiVersion::new(1, 4));
    }

    #[test]
    fn newer_host_minor_accepts_older_plugin_minor() {
        let negotiated = negotiate(ABI_VERSION, AbiVersion::new(1, 0)).expect("compatible");
        assert_eq!(negotiated.effective(), AbiVersion::new(1, 0));
    }

    #[test]
    fn different_major_versions_are_rejected_in_both_directions() {
        assert_eq!(
            negotiate(AbiVersion::new(2, 0), AbiVersion::new(1, 9)),
            Err(NegotiationError::HostMajorNewer {
                host_major: 2,
                plugin_major: 1
            })
        );
        assert_eq!(
            negotiate(AbiVersion::new(1, 9), AbiVersion::new(2, 0)),
            Err(NegotiationError::PluginMajorNewer {
                host_major: 1,
                plugin_major: 2
            })
        );
    }

    #[test]
    fn newer_plugin_minor_is_rejected() {
        assert_eq!(
            negotiate(AbiVersion::new(1, 0), AbiVersion::new(1, 1)),
            Err(NegotiationError::PluginMinorNewer {
                host_minor: 0,
                plugin_minor: 1
            })
        );
    }

    #[test]
    fn zero_major_versions_are_invalid() {
        assert_eq!(
            negotiate(AbiVersion::new(0, 1), AbiVersion::new(1, 0)),
            Err(NegotiationError::InvalidVersion { major: 0, minor: 1 })
        );
        assert_eq!(
            negotiate(AbiVersion::new(1, 0), AbiVersion::new(0, 0)),
            Err(NegotiationError::InvalidVersion { major: 0, minor: 0 })
        );
    }
}
