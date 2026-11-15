//! PROXY protocol v1/v2 header injection for L4 connections (T-L4-008, ADR-030 Q2).
//!
//! The header must be the first bytes the upstream sees, so this module renders it into a
//! `Vec<u8>` the caller writes before any payload byte. Two things make that subtle:
//!
//! - **Ordering.** When a route terminates TLS, the PROXY header still has to describe the
//!   *original* client connection, and it still has to precede the first plaintext byte the
//!   terminated stream produces. The header therefore belongs to the pipeline stage that runs
//!   after termination, carrying the pre-termination peer addresses.
//! - **v2 family bits.** A v1 header is text; a v2 header is a 16-byte signature, a version/command
//!   byte, a family/transport byte, a length and the addresses. An address family mismatch (an
//!   IPv4 peer on an IPv6 socket) is a `LOCAL` command in v2 and a v1 header cannot express it.

use std::net::SocketAddr;

/// The PROXY protocol version to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    /// `PROXY TCP4 ...` / `PROXY TCP6 ...` text header.
    V1,
    /// Binary signature + address block.
    V2,
}

impl ProxyProtocolVersion {
    /// The version this name refers to.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }

    /// The stable name used in configuration and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// The connection's addresses as the upstream should see them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyHeaderAddresses {
    /// The client (source) address, before any local TLS termination.
    pub source: SocketAddr,
    /// The listener (destination) address the client connected to.
    pub destination: SocketAddr,
}

impl ProxyHeaderAddresses {
    /// Creates the address pair for a connection.
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
        }
    }
}

/// Why a header could not be rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyHeaderError {
    message: String,
}

impl ProxyHeaderError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The reason.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ProxyHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProxyHeaderError {}

/// The v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The v2 version nibble (`0x2`) in the high half of the version/command byte.
const V2_VERSION: u8 = 0x20;
/// `PROXY` command (the connection was proxied).
const V2_COMMAND_PROXY: u8 = 0x01;
/// `LOCAL` command (the connection originates from the proxy itself).
const V2_COMMAND_LOCAL: u8 = 0x00;
/// `AF_INET` + `SOCK_STREAM`.
const V2_FAMILY_TCP4: u8 = 0x11;
/// `AF_INET6` + `SOCK_STREAM`.
const V2_FAMILY_TCP6: u8 = 0x21;
/// `AF_UNSPEC`.
const V2_FAMILY_UNSPEC: u8 = 0x00;

/// Renders the PROXY header for `addresses`.
///
/// Both addresses must share a family for a `PROXY` header; a mismatch renders the `LOCAL`
/// command instead (v2) or is an error (v1, which cannot express a local connection), because a
/// header that claimed addresses it does not have would mislead every downstream policy.
pub fn render_proxy_header(
    version: ProxyProtocolVersion,
    addresses: ProxyHeaderAddresses,
) -> Result<Vec<u8>, ProxyHeaderError> {
    let same_family = addresses.source.is_ipv4() == addresses.destination.is_ipv4();
    match version {
        ProxyProtocolVersion::V1 => render_v1(addresses, same_family),
        ProxyProtocolVersion::V2 => Ok(render_v2(addresses, same_family)),
    }
}

fn render_v1(
    addresses: ProxyHeaderAddresses,
    same_family: bool,
) -> Result<Vec<u8>, ProxyHeaderError> {
    if !same_family {
        return Err(ProxyHeaderError::new(
            "PROXY protocol v1 cannot describe a connection whose source and destination address \
             families differ; use v2",
        ));
    }
    let (source_ip, destination_ip) = (addresses.source.ip(), addresses.destination.ip());
    let family = if source_ip.is_ipv4() { "TCP4" } else { "TCP6" };
    let header = format!(
        "PROXY {family} {source_ip} {destination_ip} {} {}\r\n",
        addresses.source.port(),
        addresses.destination.port()
    );
    // v1 is ASCII by construction, but assert the length bound the protocol specifies.
    if header.len() > 107 {
        return Err(ProxyHeaderError::new(
            "PROXY protocol v1 header exceeds 107 bytes",
        ));
    }
    Ok(header.into_bytes())
}

fn render_v2(addresses: ProxyHeaderAddresses, same_family: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 216);
    out.extend_from_slice(&V2_SIGNATURE);
    if !same_family {
        out.push(V2_VERSION | V2_COMMAND_LOCAL);
        out.push(V2_FAMILY_UNSPEC);
        out.extend_from_slice(&0u16.to_be_bytes());
        return out;
    }
    match (addresses.source.ip(), addresses.destination.ip()) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) => {
            out.push(V2_VERSION | V2_COMMAND_PROXY);
            out.push(V2_FAMILY_TCP4);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
            out.extend_from_slice(&addresses.source.port().to_be_bytes());
            out.extend_from_slice(&addresses.destination.port().to_be_bytes());
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) => {
            out.push(V2_VERSION | V2_COMMAND_PROXY);
            out.push(V2_FAMILY_TCP6);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
            out.extend_from_slice(&addresses.source.port().to_be_bytes());
            out.extend_from_slice(&addresses.destination.port().to_be_bytes());
        }
        _ => {
            // INFEASIBLE: `same_family` was checked above.
            out.push(V2_VERSION | V2_COMMAND_LOCAL);
            out.push(V2_FAMILY_UNSPEC);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4() -> ProxyHeaderAddresses {
        ProxyHeaderAddresses::new(
            "192.0.2.7:5555".parse().expect("source"),
            "198.51.100.9:443".parse().expect("destination"),
        )
    }

    #[test]
    fn v1_header_is_the_text_form() {
        let header = render_proxy_header(ProxyProtocolVersion::V1, v4()).expect("v1 renders");
        assert_eq!(
            String::from_utf8(header).expect("ascii"),
            "PROXY TCP4 192.0.2.7 198.51.100.9 5555 443\r\n"
        );
    }

    #[test]
    fn v1_header_for_ipv6_uses_tcp6() {
        let addresses = ProxyHeaderAddresses::new(
            "[2001:db8::1]:5555".parse().expect("source"),
            "[2001:db8::2]:443".parse().expect("destination"),
        );
        let header = render_proxy_header(ProxyProtocolVersion::V1, addresses).expect("v1 renders");
        assert_eq!(
            String::from_utf8(header).expect("ascii"),
            "PROXY TCP6 2001:db8::1 2001:db8::2 5555 443\r\n"
        );
    }

    #[test]
    fn v2_header_is_the_binary_form() {
        let header = render_proxy_header(ProxyProtocolVersion::V2, v4()).expect("v2 renders");
        assert_eq!(&header[..12], &V2_SIGNATURE);
        assert_eq!(header[12], 0x21, "version 2, PROXY command");
        assert_eq!(header[13], V2_FAMILY_TCP4);
        assert_eq!(&header[14..16], &[0x00, 0x0C], "12 address bytes");
        assert_eq!(&header[16..20], &[192, 0, 2, 7]);
        assert_eq!(&header[20..24], &[198, 51, 100, 9]);
        assert_eq!(&header[24..26], &5555u16.to_be_bytes());
        assert_eq!(&header[26..28], &443u16.to_be_bytes());
        assert_eq!(header.len(), 28);
    }

    #[test]
    fn v2_header_for_ipv6_carries_36_address_bytes() {
        let addresses = ProxyHeaderAddresses::new(
            "[2001:db8::1]:5555".parse().expect("source"),
            "[2001:db8::2]:443".parse().expect("destination"),
        );
        let header = render_proxy_header(ProxyProtocolVersion::V2, addresses).expect("v2 renders");
        assert_eq!(header[13], V2_FAMILY_TCP6);
        assert_eq!(&header[14..16], &36u16.to_be_bytes());
        assert_eq!(header.len(), 16 + 36);
    }

    #[test]
    fn mixed_families_are_local_in_v2_and_rejected_in_v1() {
        let addresses = ProxyHeaderAddresses::new(
            "192.0.2.7:5555".parse().expect("source"),
            "[2001:db8::2]:443".parse().expect("destination"),
        );
        let error = render_proxy_header(ProxyProtocolVersion::V1, addresses)
            .expect_err("v1 cannot express a local connection");
        assert!(error.message().contains("families differ"));
        let header = render_proxy_header(ProxyProtocolVersion::V2, addresses).expect("v2 renders");
        assert_eq!(header[12], 0x20, "version 2, LOCAL command");
        assert_eq!(header[13], V2_FAMILY_UNSPEC);
        assert_eq!(&header[14..16], &[0, 0]);
        assert_eq!(header.len(), 16);
    }

    #[test]
    fn version_names_round_trip() {
        for name in ["v1", "V1", " v2 "] {
            let version = ProxyProtocolVersion::parse(name).expect("parses");
            assert_eq!(version.as_str().len(), 2);
        }
        assert!(ProxyProtocolVersion::parse("v3").is_none());
    }
}
