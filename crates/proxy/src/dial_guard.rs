//! Egress policy for request-derived upstream dials (SEC-MEDIUM-PROXY C3).
//!
//! A `reverse_proxy` dial may contain placeholders (`{http.request.header.X-Backend}:80`), and
//! `dynamic_upstreams` sources can resolve request-derived names. Stock Caddy dials whatever the
//! expansion yields, so a client that controls the expanded text can reach the cloud metadata
//! service (`169.254.169.254`), loopback-only admin interfaces or local Unix sockets
//! (`unix//var/run/docker.sock`): server-side request forgery.
//!
//! [`DialGuard`] is the secure default for those dials: it refuses `unix/` targets and a small set
//! of addresses a proxied client must never be able to pick (loopback, unspecified, link-local,
//! multicast, broadcast, the CGNAT block that hosts some metadata services and the IPv6 EC2
//! metadata prefix) unless the placeholder-free part of the configuration allows them with
//! `dial_allow`. `stock_compat true` disables the guard and restores stock Caddy's behaviour.
//!
//! The IP check runs on the *resolved* addresses at connect time (the single choke point in
//! [`crate::client`]), so a hostname that resolves to a restricted address is refused as well.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use crate::trusted_proxies::IpNet;

/// A guard for request-derived dials, built from the handler's `dial_allow` entries.
#[derive(Debug, Clone, Default)]
pub struct DialGuard {
    allowed_nets: Vec<IpNet>,
    allowed_unix_prefixes: Vec<PathBuf>,
}

impl DialGuard {
    /// Build a guard from `dial_allow` entries.
    ///
    /// Each entry is an IP address or CIDR range that may be dialed even if it is restricted
    /// (`127.0.0.0/8`, `fd00:ec2::254`), or `unix/<absolute path prefix>` (`unix//run/app`) that
    /// permits Unix-socket targets below that directory. Anything else is an error naming the
    /// entry, so a typo never silently widens or narrows the policy.
    pub fn from_allow_entries(entries: &[String]) -> Result<Self, String> {
        let mut guard = Self::default();
        for entry in entries {
            let entry = entry.trim();
            if let Some(prefix) = entry.strip_prefix("unix/") {
                let path = Path::new(prefix);
                if !path.is_absolute() {
                    return Err(format!(
                        "`{entry}`: a unix prefix must be an absolute path (`unix//run/app`)"
                    ));
                }
                if path.components().any(|part| part == Component::ParentDir) {
                    return Err(format!("`{entry}`: a unix prefix must not contain `..`"));
                }
                if path.parent().is_none() {
                    return Err(format!(
                        "`{entry}`: refusing a unix prefix that allows the whole filesystem"
                    ));
                }
                guard.allowed_unix_prefixes.push(path.to_path_buf());
            } else {
                let net = IpNet::parse(entry).map_err(|message| {
                    format!("`{entry}` is neither an IP address/CIDR nor `unix/<path>`: {message}")
                })?;
                guard.allowed_nets.push(net);
            }
        }
        Ok(guard)
    }

    /// Whether the resolved address may be dialed.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        let ip = ip.to_canonical();
        if !is_restricted_ip(ip) || self.allowed_nets.iter().any(|net| net.contains(ip)) {
            return Ok(());
        }
        Err(format!(
            "dial target {ip} is a loopback, link-local or otherwise restricted address and is \
             not listed in `dial_allow`"
        ))
    }

    /// Whether the Unix-socket path may be dialed. Relative paths and paths containing `..` are
    /// never allowed; otherwise the path must lie below one of the configured prefixes.
    pub fn check_unix(&self, path: &Path) -> Result<(), String> {
        let lexically_safe =
            path.is_absolute() && !path.components().any(|part| part == Component::ParentDir);
        if lexically_safe
            && self
                .allowed_unix_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return Ok(());
        }
        Err(format!(
            "dial target unix socket {} is not below a `unix/<path>` entry of `dial_allow`",
            path.display()
        ))
    }
}

/// Addresses a request-derived dial may not reach unless `dial_allow` lists them.
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                // 100.64.0.0/10 (shared address space; Alibaba metadata 100.100.100.200).
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40)
                // Oracle Cloud metadata.
                || ip == Ipv4Addr::new(192, 0, 0, 192)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                // fe80::/10 link-local.
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                // fd00:ec2::/32 (AWS IPv6 instance metadata).
                || (ip.segments()[0] == 0xfd00 && ip.segments()[1] == 0x0ec2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn restricted_addresses_are_refused_by_default() {
        let guard = DialGuard::default();
        for denied in [
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "169.254.169.254",
            "169.254.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "100.100.100.200",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.192",
            "::1",
            "::",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "fd00:ec2::254",
            // IPv4-mapped spellings of restricted v4 addresses are canonicalised first.
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                guard.check_ip(ip(denied)).is_err(),
                "{denied} must be denied"
            );
        }
    }

    #[test]
    fn ordinary_addresses_are_allowed_by_default() {
        let guard = DialGuard::default();
        for allowed in [
            "203.0.113.7",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "192.0.0.193",
            "2001:db8::1",
            "fd00::1",
            "fd00:ec3::1",
            "fec0::1",
            "::ffff:203.0.113.7",
        ] {
            assert!(
                guard.check_ip(ip(allowed)).is_ok(),
                "{allowed} must be allowed"
            );
        }
    }

    #[test]
    fn dial_allow_entries_open_exactly_what_they_name() {
        let guard = DialGuard::from_allow_entries(&[
            "127.0.0.0/8".to_string(),
            "169.254.10.10".to_string(),
            "fd00:ec2::254/128".to_string(),
        ])
        .unwrap();
        assert!(guard.check_ip(ip("127.0.0.1")).is_ok());
        assert!(guard.check_ip(ip("::ffff:127.0.0.1")).is_ok());
        assert!(guard.check_ip(ip("169.254.10.10")).is_ok());
        assert!(guard.check_ip(ip("fd00:ec2::254")).is_ok());
        // Neighbouring restricted addresses stay denied.
        assert!(guard.check_ip(ip("169.254.169.254")).is_err());
        assert!(guard.check_ip(ip("::1")).is_err());
        assert!(guard.check_ip(ip("fe80::1")).is_err());
    }

    #[test]
    fn unix_targets_are_denied_unless_below_an_allowed_prefix() {
        let none = DialGuard::default();
        assert!(none.check_unix(Path::new("/var/run/docker.sock")).is_err());

        let guard = DialGuard::from_allow_entries(&["unix//run/app".to_string()]).unwrap();
        assert!(guard.check_unix(Path::new("/run/app/web.sock")).is_ok());
        assert!(guard.check_unix(Path::new("/run/app")).is_ok());
        assert!(guard.check_unix(Path::new("/run/app/sub/web.sock")).is_ok());
        // Sibling directory sharing a string prefix, other trees, relative and traversal paths.
        assert!(guard.check_unix(Path::new("/run/app2/web.sock")).is_err());
        assert!(guard.check_unix(Path::new("/var/run/docker.sock")).is_err());
        assert!(guard.check_unix(Path::new("run/app/web.sock")).is_err());
        assert!(guard
            .check_unix(Path::new("/run/app/../docker.sock"))
            .is_err());
    }

    #[test]
    fn malformed_allow_entries_are_rejected_loudly() {
        for bad in [
            "not-an-ip",
            "example.com",
            "10.0.0.0/33",
            "unix/relative/path",
            "unix/",
            "unix//",
            "unix//run/../etc",
            "",
        ] {
            let error = DialGuard::from_allow_entries(&[bad.to_string()])
                .expect_err(&format!("`{bad}` must be rejected"));
            assert!(
                error.contains(&format!("`{bad}`")) || bad.is_empty(),
                "{error}"
            );
        }
    }
}
