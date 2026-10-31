//! Caddy listen-address parsing.
//!
//! Caddy listen addresses use the form `[network/]address`, where the network defaults to `tcp`.
//! Examples: `":443"`, `"localhost:2019"`, `"[::1]:443"`, `"tcp/0.0.0.0:8080"`,
//! `"udp/:443"`, `"unix//run/caddy.sock"` (the path is `/run/caddy.sock`).

use std::fmt;
use std::net::SocketAddr;

use crate::error::{Error, Result};

/// Network of a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// TCP (the default).
    Tcp,
    /// UDP, used by HTTP/3.
    Udp,
    /// Unix domain socket.
    Unix,
}

impl Network {
    /// The configuration spelling of this network.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
            Network::Unix => "unix",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed Caddy listen address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenAddr {
    /// Transport network.
    pub network: Network,
    /// Address portion: `host:port` for TCP/UDP, filesystem path for Unix.
    pub address: String,
}

impl ListenAddr {
    /// Parse a Caddy listen-address string.
    pub fn parse(input: &str) -> std::result::Result<Self, String> {
        let (network, address) = match input.split_once('/') {
            Some((prefix, rest)) if matches!(prefix, "tcp" | "udp" | "unix") => match prefix {
                "tcp" => (Network::Tcp, rest),
                "udp" => (Network::Udp, rest),
                _ => (Network::Unix, rest),
            },
            _ => (Network::Tcp, input),
        };

        if address.trim().is_empty() {
            return Err("address is empty".to_string());
        }

        match network {
            Network::Unix => {
                if !address.starts_with('/') {
                    return Err("unix socket path must be absolute".to_string());
                }
                Ok(Self {
                    network,
                    address: address.to_string(),
                })
            }
            Network::Tcp | Network::Udp => {
                parse_host_port(address)?;
                Ok(Self {
                    network,
                    address: address.to_string(),
                })
            }
        }
    }

    /// Parse a listen address, producing a located [`Error`].
    pub fn parse_at(input: &str, path: impl Into<String>) -> Result<Self> {
        Self::parse(input).map_err(|reason| Error::InvalidListen {
            value: input.to_string(),
            path: path.into(),
            reason,
        })
    }

    /// The host portion of a TCP/UDP address (`""` for a wildcard bind).
    pub fn host(&self) -> &str {
        match self.network {
            Network::Unix => "",
            _ => split_host_port(&self.address)
                .map(|(host, _)| host)
                .unwrap_or(""),
        }
    }

    /// The port portion of a TCP/UDP address.
    pub fn port(&self) -> Option<u16> {
        match self.network {
            Network::Unix => None,
            _ => split_host_port(&self.address).and_then(|(_, port)| port.parse().ok()),
        }
    }

    /// Resolve a concrete socket address when the host is an IP literal or empty (wildcard).
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let (host, port) = split_host_port(&self.address)?;
        let port: u16 = port.parse().ok()?;
        if host.is_empty() {
            return Some(SocketAddr::from(([0, 0, 0, 0], port)));
        }
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let ip: std::net::IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    }

    /// Whether this listener uses TLS by convention (port 443).
    pub fn looks_https(&self) -> bool {
        self.port() == Some(443)
    }
}

fn parse_host_port(address: &str) -> std::result::Result<(), String> {
    let (_, port) = split_host_port(address).ok_or_else(|| {
        "expected `host:port` (IPv6 literals must be bracketed, e.g. `[::1]:443`)".to_string()
    })?;
    match port.parse::<u16>() {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("port `{port}` is not a valid u16")),
    }
}

fn split_host_port(address: &str) -> Option<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &address[..end + 2];
        let port = address[end + 2..].strip_prefix(':')?;
        return Some((host, port));
    }
    let (host, port) = address.rsplit_once(':')?;
    if port.is_empty() {
        return None;
    }
    Some((host, port))
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.network {
            Network::Tcp => f.write_str(&self.address),
            _ => write!(f, "{}/{}", self.network, self.address),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_caddy_spellings() {
        let cases = [
            (":443", Network::Tcp, ":443"),
            ("localhost:2019", Network::Tcp, "localhost:2019"),
            ("[::1]:443", Network::Tcp, "[::1]:443"),
            ("tcp/0.0.0.0:8080", Network::Tcp, "0.0.0.0:8080"),
            ("udp/:443", Network::Udp, ":443"),
            ("unix//run/caddy.sock", Network::Unix, "/run/caddy.sock"),
        ];
        for (input, network, address) in cases {
            let parsed = ListenAddr::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(parsed.network, network, "network for {input}");
            assert_eq!(parsed.address, address, "address for {input}");
        }
    }

    #[test]
    fn rejects_malformed_addresses_with_named_input() {
        for input in ["", "localhost", "tcp/", "unix/relative.sock", "[::1]"] {
            let err = ListenAddr::parse(input).expect_err(input);
            assert!(!err.is_empty(), "reason for {input}");
        }
    }

    #[test]
    fn extracts_host_and_port() {
        let addr = ListenAddr::parse("[::1]:8443").unwrap();
        assert_eq!(addr.host(), "[::1]");
        assert_eq!(addr.port(), Some(8443));
        assert_eq!(addr.socket_addr(), Some("[::1]:8443".parse().unwrap()));
    }
}
