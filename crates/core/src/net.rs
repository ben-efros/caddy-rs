//! IP range matching shared by every crate that compares a peer address with a configured range
//! (SEC-MEDIUM-PROXY C2).
//!
//! Listeners bind `[::]` with `IPV6_V6ONLY` off, so an IPv4 client can be reported as the
//! IPv4-mapped address `::ffff:a.b.c.d`. Go's `net` reports such peers as plain IPv4 and Caddy
//! compares after `Unmap()`; a naive family-exact comparison makes `203.0.113.0/24` miss the
//! mapped spelling of `203.0.113.5` (a deny bypass for `not remote_ip ...` and the like).

use std::net::IpAddr;

/// Whether `ip` is inside `base/prefix`, treating IPv4-mapped IPv6 addresses as their IPv4 form.
///
/// Both the address as given and its [`IpAddr::to_canonical`] form are tried, so a genuine IPv6
/// range that covers the mapped block (`::/0`) keeps matching mapped peers. A range written in the
/// mapped form (`::ffff:a.b.c.d/n`, `n >= 96`) is the IPv4 range `a.b.c.d/(n-96)`. An IPv4 address
/// never matches an unrelated IPv6 range and vice versa. A `prefix` larger than the family's width
/// never matches anything.
pub fn ip_in_net(base: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    let (base, prefix) = match base {
        IpAddr::V6(v6) if prefix >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), prefix - 96),
            None => (base, prefix),
        },
        _ => (base, prefix),
    };
    in_net_exact(base, prefix, ip) || in_net_exact(base, prefix, ip.to_canonical())
}

fn in_net_exact(base: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (base, ip) {
        (IpAddr::V4(base), IpAddr::V4(ip)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            (u32::from(base) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            (u128::from(base) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn plain_families_match_exactly() {
        assert!(ip_in_net(ip("10.0.0.0"), 8, ip("10.9.9.9")));
        assert!(!ip_in_net(ip("10.0.0.0"), 8, ip("11.0.0.1")));
        assert!(ip_in_net(ip("2001:db8::"), 32, ip("2001:db8::1")));
        assert!(!ip_in_net(ip("2001:db8::"), 32, ip("2001:db9::1")));
        assert!(ip_in_net(ip("0.0.0.0"), 0, ip("203.0.113.5")));
        assert!(!ip_in_net(ip("2001:db8::"), 32, ip("10.0.0.1")));
        assert!(!ip_in_net(ip("10.0.0.0"), 8, ip("2001:db8::1")));
        assert!(!ip_in_net(ip("10.0.0.0"), 33, ip("10.0.0.1")));
    }

    #[test]
    fn mapped_peers_match_ipv4_ranges() {
        assert!(ip_in_net(ip("203.0.113.0"), 24, ip("::ffff:203.0.113.5")));
        assert!(!ip_in_net(ip("203.0.113.0"), 24, ip("::ffff:198.51.100.5")));
        // `/0` of either family.
        assert!(ip_in_net(ip("0.0.0.0"), 0, ip("::ffff:203.0.113.5")));
        assert!(ip_in_net(ip("::"), 0, ip("::ffff:203.0.113.5")));
    }

    #[test]
    fn ranges_written_in_the_mapped_form_are_ipv4_ranges() {
        assert!(ip_in_net(ip("::ffff:203.0.113.0"), 120, ip("203.0.113.9")));
        assert!(ip_in_net(
            ip("::ffff:203.0.113.0"),
            120,
            ip("::ffff:203.0.113.9")
        ));
        assert!(!ip_in_net(ip("::ffff:203.0.113.0"), 120, ip("203.0.114.9")));
        // A host route, and `::ffff:0:0/96` which this implementation reads as all of IPv4
        // (a documented deviation from Go's netip.Prefix).
        assert!(ip_in_net(ip("::ffff:10.0.0.1"), 128, ip("10.0.0.1")));
        assert!(ip_in_net(ip("::ffff:0.0.0.0"), 96, ip("203.0.113.5")));
        // A prefix shorter than 96 stays an IPv6 range: it matches the mapped spelling as given.
        assert!(ip_in_net(
            ip("::ffff:0.0.0.0"),
            95,
            ip("::ffff:203.0.113.5")
        ));
    }
}
