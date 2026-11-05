//! Server-level `trusted_proxies` handling (Caddy `apps.http.servers.<name>.trusted_proxies`).
//!
//! Caddy's HTTP app resolves, for every request, whether the peer connection is a trusted proxy and
//! what the effective client IP is (the left-most untrusted address in the client IP headers, or
//! the strict right-to-left walk when `trusted_proxies_strict` is set). Handlers then read the
//! `trusted_proxy`/`client_ip` request variables:
//!
//! * `reverse_proxy` forwards prior `X-Forwarded-*` values only when the peer is trusted.
//! * `client_ip_hash` hashes the effective client IP.
//!
//! caddy-rs' HTTP engine does not yet apply this server option in its request pipeline, so this
//! module provides the parsing/resolution logic plus [`ServerTrustedProxies::apply`], which sets
//! the Caddy-compatible request variables (`trusted_proxy` = `"true"`/`"false"`, `client_ip`).
//! The server runtime calls `apply` when preparing requests (tracked as the server-side half of
//! T-PROXY-025); the reverse_proxy handler already consumes those variables, so behavior switches
//! on as soon as that wiring lands.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;

use caddy_rs_http::{Error as HttpError, Request, Result as HttpResult};

/// Caddy's built-in `private_ranges` set (internal.PrivateRangesCIDR).
pub const PRIVATE_RANGES: &[&str] = &[
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "127.0.0.1/8",
    "fd00::/8",
    "::1",
];

/// One IP network (single addresses become /32 or /128 networks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    network: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse a single IP address or CIDR expression.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => {
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| format!("invalid CIDR prefix in `{value}`"))?;
                (address, Some(prefix))
            }
            None => (value, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("`{value}` is not an IP address or CIDR range"))?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max_prefix);
        if prefix > max_prefix {
            return Err(format!("CIDR prefix /{prefix} is too large for `{value}`"));
        }
        Ok(Self {
            network: address,
            prefix,
        })
    }

    /// Whether `address` falls inside this network (same address family only).
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// Parsed server-level trusted-proxy settings (`apps.http.servers.<name>` fields).
#[derive(Debug, Clone, Default)]
pub struct ServerTrustedProxies {
    ranges: Vec<IpNet>,
    strict: bool,
    unix: bool,
    client_ip_headers: Vec<String>,
}

impl ServerTrustedProxies {
    /// Parse the trusted-proxy fields of one `apps.http.servers.<name>` object.
    ///
    /// Accepts Caddy's module shape for `trusted_proxies` (`{"source": "static", "ranges": [...]}`)
    /// and, for convenience, a bare array of range strings. Range entries may be CIDR ranges,
    /// single IPs, `private_ranges` (Caddy's built-in set), `none`, or `all`.
    pub fn from_server_json(server: &Value, path: &str) -> HttpResult<Self> {
        let object = server
            .as_object()
            .ok_or_else(|| invalid(path, "server configuration must be an object"))?;
        let ranges = match object.get("trusted_proxies") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => parse_trusted_proxies_value(value, &format!("{path}.trusted_proxies"))?,
        };
        let strict = match object.get("trusted_proxies_strict") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(strict)) => *strict,
            Some(Value::Number(strict)) => strict.as_u64().is_some_and(|strict| strict > 0),
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.trusted_proxies_strict"),
                    "`trusted_proxies_strict` must be a boolean",
                ))
            }
        };
        let unix = object
            .get("trusted_proxies_unix")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let client_ip_headers = match object.get("client_ip_headers") {
            None | Some(Value::Null) => vec!["X-Forwarded-For".to_string()],
            Some(value) => {
                let entries = value.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{path}.client_ip_headers"),
                        "`client_ip_headers` must be an array of header names",
                    )
                })?;
                let mut headers = Vec::with_capacity(entries.len());
                for (index, entry) in entries.iter().enumerate() {
                    let header = entry.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.client_ip_headers[{index}]"),
                            "`client_ip_headers` entries must be strings",
                        )
                    })?;
                    headers.push(header.to_string());
                }
                if headers.is_empty() {
                    vec!["X-Forwarded-For".to_string()]
                } else {
                    headers
                }
            }
        };
        Ok(Self {
            ranges,
            strict,
            unix,
            client_ip_headers,
        })
    }

    /// The configured ranges (empty when `trusted_proxies` is absent or `none`).
    pub fn ranges(&self) -> &[IpNet] {
        &self.ranges
    }

    /// Whether `trusted_proxies_strict` is enabled.
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Whether Unix-socket peers are trusted when `trusted_proxies_unix` is enabled.
    pub fn unix(&self) -> bool {
        self.unix
    }

    /// Resolve `(trusted, client_ip)` for a request, mirroring Caddy's `determineTrustedProxy`.
    ///
    /// The returned client IP is a bare address (no port), or the peer address when no usable
    /// client IP header is present. A request without a peer address is treated as a Unix-socket
    /// peer (`"@"` in Caddy).
    pub fn determine(&self, request: &Request) -> (bool, String) {
        let Some(peer) = request.remote_addr else {
            if self.unix {
                let client_ip = if self.strict {
                    strict_untrusted_client_ip(request, &self.client_ip_headers, &self.ranges, "")
                } else {
                    trusted_real_client_ip(request, &self.client_ip_headers, "")
                };
                return (true, client_ip);
            }
            return (false, String::new());
        };
        let peer_ip = peer.ip();
        let trusted = self.ranges.iter().any(|network| network.contains(peer_ip));
        if !trusted {
            return (false, peer_ip.to_string());
        }
        let client_ip = if self.strict {
            strict_untrusted_client_ip(
                request,
                &self.client_ip_headers,
                &self.ranges,
                &peer_ip.to_string(),
            )
        } else {
            trusted_real_client_ip(request, &self.client_ip_headers, &peer_ip.to_string())
        };
        (true, client_ip)
    }

    /// Set Caddy's `trusted_proxy`/`client_ip` request variables (server request-preparation hook).
    pub fn apply(&self, request: &mut Request) -> (bool, String) {
        let (trusted, client_ip) = self.determine(request);
        request.vars.insert(
            "trusted_proxy".to_string(),
            if trusted { "true" } else { "false" }.to_string(),
        );
        request
            .vars
            .insert("client_ip".to_string(), client_ip.clone());
        (trusted, client_ip)
    }
}

fn parse_trusted_proxies_value(value: &Value, path: &str) -> HttpResult<Vec<IpNet>> {
    // Caddy JSON: {"source": "static", "ranges": [...]}. Bare arrays are accepted too so the
    // helper can be used from tests/adapters that have not materialised the module object.
    let (source, entries) = match value {
        Value::Object(object) => {
            let source = object
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("static");
            if source != "static" {
                return Err(HttpError::NotImplemented {
                    feature: "non-static trusted_proxies IP range source modules",
                    tracking_id: "TRUSTED-PROXIES-SOURCE",
                });
            }
            let entries = object
                .get("ranges")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            (source.to_string(), entries)
        }
        Value::Array(entries) => ("static".to_string(), entries.clone()),
        _ => {
            return Err(invalid(
                path,
                "`trusted_proxies` must be an IP range source object or an array of ranges",
            ))
        }
    };
    let _ = source;
    let mut ranges = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let text = entry.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}.ranges[{index}]"),
                "trusted proxy ranges must be strings",
            )
        })?;
        for range in expand_range(text)
            .map_err(|message| invalid(&format!("{path}.ranges[{index}]"), message))?
        {
            ranges.push(
                IpNet::parse(&range)
                    .map_err(|message| invalid(&format!("{path}.ranges[{index}]"), message))?,
            );
        }
    }
    Ok(ranges)
}

fn expand_range(text: &str) -> Result<Vec<String>, String> {
    match text.trim() {
        "private_ranges" => Ok(PRIVATE_RANGES
            .iter()
            .map(|value| value.to_string())
            .collect()),
        "none" => Ok(Vec::new()),
        "all" => Ok(vec![
            Ipv4Addr::UNSPECIFIED.to_string() + "/0",
            Ipv6Addr::UNSPECIFIED.to_string() + "/0",
        ]),
        other => Ok(vec![other.to_string()]),
    }
}

/// Caddy's `trustedRealClientIP`: first valid left-most IP from the client IP headers.
fn trusted_real_client_ip(request: &Request, headers: &[String], fallback: &str) -> String {
    let mut values = Vec::new();
    for header in headers {
        for value in request.headers.get_all(header.as_str()) {
            if let Ok(value) = value.to_str() {
                values.push(value.to_string());
            }
        }
    }
    for part in values.join(",").split(',') {
        if let Some(ip) = parse_client_ip(part) {
            return ip.to_string();
        }
    }
    fallback.to_string()
}

/// Caddy's `strictUntrustedClientIp`: right-to-left walk returning the first untrusted IP.
fn strict_untrusted_client_ip(
    request: &Request,
    headers: &[String],
    trusted_ranges: &[IpNet],
    fallback: &str,
) -> String {
    for header in headers {
        let mut values = Vec::new();
        for value in request.headers.get_all(header.as_str()) {
            if let Ok(value) = value.to_str() {
                values.push(value.to_string());
            }
        }
        let joined = values.join(",");
        for part in joined.split(',').rev() {
            if let Some(ip) = parse_client_ip(part) {
                if !trusted_ranges.iter().any(|network| network.contains(ip)) {
                    return ip.to_string();
                }
            }
        }
    }
    fallback.to_string()
}

fn parse_client_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return Some(address.ip());
    }
    let value = value.strip_prefix('[').unwrap_or(value);
    let value = value.split(']').next().unwrap_or(value);
    value
        .split('%')
        .next()
        .unwrap_or(value)
        .parse::<IpAddr>()
        .ok()
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn request(peer: Option<&str>, forwarded_for: Option<&str>) -> Request {
        let mut request = Request::new(Method::GET, "/".parse().unwrap());
        request.remote_addr = peer.and_then(|peer| peer.parse().ok());
        if let Some(forwarded_for) = forwarded_for {
            request
                .headers
                .insert("x-forwarded-for", forwarded_for.parse().unwrap());
        }
        request
    }

    #[test]
    fn parses_cidr_private_ranges_none_and_all() {
        let server = serde_json::json!({
            "trusted_proxies": {
                "source": "static",
                "ranges": ["10.0.0.0/8", "203.0.113.7", "private_ranges", "none"]
            }
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        assert!(trusted
            .ranges()
            .iter()
            .any(|range| range.contains("10.1.2.3".parse().unwrap())));
        assert!(trusted
            .ranges()
            .iter()
            .any(|range| range.contains("203.0.113.7".parse().unwrap())));
        assert!(trusted
            .ranges()
            .iter()
            .any(|range| range.contains("192.168.1.1".parse().unwrap())));

        let server =
            serde_json::json!({"trusted_proxies": {"source": "static", "ranges": ["all"]}});
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        assert!(trusted
            .ranges()
            .iter()
            .any(|range| range.contains("8.8.8.8".parse().unwrap())));
        assert!(trusted
            .ranges()
            .iter()
            .any(|range| range.contains("2001:db8::1".parse().unwrap())));

        let server =
            serde_json::json!({"trusted_proxies": {"source": "static", "ranges": ["none"]}});
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        assert!(trusted.ranges().is_empty());

        let error = ServerTrustedProxies::from_server_json(
            &serde_json::json!({"trusted_proxies": {"source": "magic", "ranges": []}}),
            "server",
        )
        .err()
        .expect("unknown IP range source must fail");
        assert!(
            error.to_string().contains("TRUSTED-PROXIES-SOURCE"),
            "{error}"
        );
    }

    #[test]
    fn trusted_peer_uses_leftmost_forwarded_for() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["10.0.0.0/8"]}
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        let chained = request(Some("10.0.0.5:1234"), Some("203.0.113.9, 10.0.0.2"));
        let (is_trusted, client_ip) = trusted.determine(&chained);
        assert!(is_trusted);
        assert_eq!(client_ip, "203.0.113.9");
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["10.0.0.0/8"]}
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        let request = request(Some("198.51.100.7:1234"), Some("203.0.113.9"));
        let (is_trusted, client_ip) = trusted.determine(&request);
        assert!(!is_trusted);
        assert_eq!(client_ip, "198.51.100.7");
    }

    #[test]
    fn strict_mode_walks_right_to_left() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["10.0.0.0/8"]},
            "trusted_proxies_strict": 1
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        assert!(trusted.strict());
        let chained = request(Some("10.0.0.5:1234"), Some("203.0.113.9, 10.0.0.2"));
        let (is_trusted, client_ip) = trusted.determine(&chained);
        assert!(is_trusted);
        assert_eq!(
            client_ip, "203.0.113.9",
            "right-most trusted hop is skipped"
        );

        // All hops trusted: the direct peer is the effective client.
        let all_trusted = request(Some("10.0.0.5:1234"), Some("10.0.0.2, 10.0.0.3"));
        assert_eq!(trusted.determine(&all_trusted).1, "10.0.0.5");
    }

    #[test]
    fn unix_peers_are_trusted_only_when_configured() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": []},
            "trusted_proxies_unix": true
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        assert!(trusted.unix());
        let request = request(None, Some("203.0.113.9"));
        let (is_trusted, client_ip) = trusted.determine(&request);
        assert!(is_trusted);
        assert_eq!(client_ip, "203.0.113.9");

        let untrusted = ServerTrustedProxies::from_server_json(
            &serde_json::json!({"trusted_proxies": {"source": "static", "ranges": []}}),
            "server",
        )
        .unwrap();
        assert_eq!(untrusted.determine(&request), (false, String::new()));
    }

    #[test]
    fn apply_sets_caddy_compatible_request_variables() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["10.0.0.0/8"]}
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        let mut trusted_request = request(Some("10.0.0.5:1234"), Some("203.0.113.9"));
        trusted.apply(&mut trusted_request);
        assert_eq!(trusted_request.vars["trusted_proxy"], "true");
        assert_eq!(trusted_request.vars["client_ip"], "203.0.113.9");

        let mut untrusted_request = request(Some("198.51.100.7:1234"), None);
        trusted.apply(&mut untrusted_request);
        assert_eq!(untrusted_request.vars["trusted_proxy"], "false");
        assert_eq!(untrusted_request.vars["client_ip"], "198.51.100.7");
    }

    #[test]
    fn custom_client_ip_headers_are_honoured() {
        let server = serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["10.0.0.0/8"]},
            "client_ip_headers": ["X-Real-IP", "X-Forwarded-For"]
        });
        let trusted = ServerTrustedProxies::from_server_json(&server, "server").unwrap();
        let mut request = request(Some("10.0.0.5:1234"), Some("203.0.113.9"));
        request
            .headers
            .insert("x-real-ip", "198.51.100.12".parse().unwrap());
        assert_eq!(trusted.determine(&request).1, "198.51.100.12");
    }
}
