//! Upstream server representation and dial parsing.
//!
//! Caddy "network addresses" support plain `host:port` TCP dials as well as Unix domain sockets.
//! A Unix-socket dial is written with the `unix/` network prefix, either as `unix//run/app.sock`
//! (the canonical Caddy form for an absolute path) or as `unix/run/app.sock` for a relative one.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// How an upstream is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Plaintext HTTP over TCP to `address` (`host:port`).
    Tcp {
        /// `host:port` dial target.
        address: String,
    },
    /// Plaintext HTTP over a Unix domain socket.
    #[cfg(unix)]
    Unix {
        /// Filesystem path of the socket.
        path: PathBuf,
    },
}

/// A proxy upstream.
#[derive(Debug)]
pub struct Upstream {
    /// Original dial value, for logs and error messages.
    pub dial: String,
    /// Whether this upstream TLS is required.
    pub tls: bool,
    transport: Transport,
    healthy: AtomicBool,
    active_connections: AtomicUsize,
    /// Caddy `upstreams[].max_requests`: maximum simultaneous requests (`None` = unlimited).
    max_requests: Option<usize>,
    /// Cumulative number of proxy attempts sent to this upstream (live admin counter).
    num_requests: AtomicU64,
    /// Cumulative number of failed attempts to this upstream (live admin counter).
    fails: AtomicU64,
}

impl Upstream {
    /// Construct a TCP upstream from an already-validated `host:port` dial.
    pub fn new(dial: impl Into<String>, tls: bool) -> Self {
        let dial = dial.into();
        Self {
            transport: Transport::Tcp {
                address: dial.clone(),
            },
            dial,
            tls,
            healthy: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
            max_requests: None,
            num_requests: AtomicU64::new(0),
            fails: AtomicU64::new(0),
        }
    }

    /// Parse a Caddy `dial` value.
    ///
    /// Supported forms:
    ///
    /// * `host:port` — plain TCP.
    /// * `unix//absolute/path.sock` and `unix/relative/path.sock` — Unix domain socket.
    ///
    /// Schemes, placeholders and malformed addresses are rejected by name so that unsupported
    /// configuration never silently degrades into a wrong dial.
    pub fn parse_dial(dial: &str, tls: bool) -> Result<Self, String> {
        if dial.is_empty() {
            return Err("upstream dial address is empty".to_string());
        }
        if dial.contains('{') {
            return Err(format!(
                "upstream `{dial}` uses placeholders, which are not implemented (HTTP-PLACEHOLDERS)"
            ));
        }
        if dial == "unix" || dial.starts_with("unix/") {
            let path = dial.strip_prefix("unix/").unwrap_or_default();
            if path.is_empty() {
                return Err(format!(
                    "unix socket upstream `{dial}` is missing a socket path"
                ));
            }
            #[cfg(unix)]
            {
                return Ok(Self {
                    dial: dial.to_string(),
                    tls,
                    transport: Transport::Unix {
                        path: PathBuf::from(path),
                    },
                    healthy: AtomicBool::new(true),
                    active_connections: AtomicUsize::new(0),
                    max_requests: None,
                    num_requests: AtomicU64::new(0),
                    fails: AtomicU64::new(0),
                });
            }
            #[cfg(not(unix))]
            {
                return Err(format!(
                    "unix socket upstream `{dial}` is not supported on this platform"
                ));
            }
        }
        if let Some((scheme, _)) = dial.split_once("://") {
            return Err(format!(
                "upstream dial `{dial}` must not include a scheme (`{scheme}://`)"
            ));
        }
        let Some((host, port)) = dial.rsplit_once(':') else {
            return Err(format!("upstream dial `{dial}` is missing a port"));
        };
        if host.is_empty() {
            return Err(format!("upstream dial `{dial}` is missing a host"));
        }
        if port.parse::<u16>().is_err() {
            return Err(format!(
                "upstream dial `{dial}` has an invalid port `{port}` (a single numeric port is required)"
            ));
        }
        Ok(Self::new(dial, tls))
    }

    /// How this upstream is reached.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Build the absolute URI hyper uses for a request to this upstream.
    ///
    /// The scheme selects both the network transport and whether TLS is applied:
    ///
    /// * `http://host:port` — plain TCP.
    /// * `https://host:port` — TCP + TLS (`transport.tls` configured).
    /// * `unix://<hex-encoded socket path>` — plain Unix socket.
    /// * `unixs://<hex-encoded socket path>` — Unix socket + TLS.
    ///
    /// The socket path is hex-encoded because a URI authority cannot contain `/`;
    /// [`crate::client::UpstreamConnector`] decodes it again before dialing.
    pub fn url(&self, path_and_query: &str) -> String {
        match (&self.transport, self.tls) {
            (Transport::Tcp { address }, false) => format!("http://{address}{path_and_query}"),
            (Transport::Tcp { address }, true) => format!("https://{address}{path_and_query}"),
            #[cfg(unix)]
            (Transport::Unix { path }, false) => {
                format!("unix://{}{path_and_query}", encode_unix_authority(path))
            }
            #[cfg(unix)]
            (Transport::Unix { path }, true) => {
                format!("unixs://{}{path_and_query}", encode_unix_authority(path))
            }
        }
    }

    /// Host header used when a request does not carry one (health checks use `localhost` for Unix
    /// sockets, matching Caddy).
    pub fn fallback_host(&self) -> &str {
        match &self.transport {
            Transport::Tcp { address } => address,
            #[cfg(unix)]
            Transport::Unix { .. } => "localhost",
        }
    }

    /// Caddy `upstreams[].max_requests`, when configured.
    pub fn max_requests(&self) -> Option<usize> {
        self.max_requests
    }

    /// Configure the maximum simultaneous request count (builder style).
    pub fn with_max_requests(mut self, max_requests: Option<usize>) -> Self {
        self.max_requests = max_requests;
        self
    }

    /// Count one proxy attempt against this upstream (live `/reverse_proxy/upstreams` counter).
    pub fn record_request(&self) {
        self.num_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one failed attempt against this upstream (live `/reverse_proxy/upstreams` counter).
    pub fn record_failure(&self) {
        self.fails.fetch_add(1, Ordering::Relaxed);
    }

    /// Count `count` passive-health failure strikes against this upstream.
    pub fn record_failures(&self, count: u32) {
        if count > 0 {
            self.fails.fetch_add(u64::from(count), Ordering::Relaxed);
        }
    }

    /// Cumulative proxy attempts sent to this upstream.
    pub fn num_requests(&self) -> u64 {
        self.num_requests.load(Ordering::Relaxed)
    }

    /// Cumulative failed proxy attempts for this upstream.
    pub fn fails(&self) -> u64 {
        self.fails.load(Ordering::Relaxed)
    }

    /// Caddy `Upstream.Full()`: the configured simultaneous-request limit is reached.
    pub fn is_full(&self) -> bool {
        self.max_requests
            .is_some_and(|max| self.active_connections() >= max)
    }

    /// Health observed by active/passive checks.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Mark the upstream healthy or unhealthy.
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Release);
    }

    /// Number of in-flight proxied requests.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Acquire)
    }

    /// Increment in-flight count.
    pub fn connection_started(&self) -> ConnectionGuard<'_> {
        self.active_connections.fetch_add(1, Ordering::AcqRel);
        ConnectionGuard { upstream: self }
    }
}

/// RAII guard decrementing an upstream's in-flight count.
pub struct ConnectionGuard<'a> {
    upstream: &'a Upstream,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.upstream
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Hex-encode the socket path for use as a URI authority.
#[cfg(unix)]
fn encode_unix_authority(path: &std::path::Path) -> String {
    use std::fmt::Write;
    use std::os::unix::ffi::OsStrExt;

    let mut encoded = String::with_capacity(path.as_os_str().as_bytes().len() * 2);
    for byte in path.as_os_str().as_bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Decode a URI authority produced by [`encode_unix_authority`].
#[cfg(unix)]
pub(crate) fn decode_unix_authority(authority: &str) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStringExt;

    if authority.is_empty() {
        return Err("unix socket URI is missing an encoded path".to_string());
    }
    if authority.len() % 2 != 0 {
        return Err(format!(
            "unix socket URI authority `{authority}` has an odd number of hex digits"
        ));
    }
    let mut bytes = Vec::with_capacity(authority.len() / 2);
    let raw = authority.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let high = hex_digit(raw[index])?;
        let low = hex_digit(raw[index + 1])?;
        bytes.push(high * 16 + low);
        index += 2;
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(unix)]
fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!(
            "invalid hex digit `{}` in unix socket URI authority",
            other as char
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_dial() {
        let upstream = Upstream::parse_dial("localhost:8096", false).unwrap();
        assert_eq!(upstream.dial, "localhost:8096");
        assert_eq!(
            upstream.url("/health?x=1"),
            "http://localhost:8096/health?x=1"
        );
        assert_eq!(upstream.fallback_host(), "localhost:8096");
        assert!(upstream.is_healthy());
    }

    #[test]
    fn parses_ipv6_dial() {
        let upstream = Upstream::parse_dial("[::1]:8096", false).unwrap();
        assert_eq!(upstream.fallback_host(), "[::1]:8096");
    }

    #[test]
    fn rejects_scheme_missing_port_and_bad_port() {
        assert!(Upstream::parse_dial("http://localhost:8096", false).is_err());
        assert!(Upstream::parse_dial("localhost", false).is_err());
        let error = Upstream::parse_dial("localhost:http", false).unwrap_err();
        assert!(error.contains("invalid port"), "{error}");
        let error = Upstream::parse_dial(":8080", false).unwrap_err();
        assert!(error.contains("missing a host"), "{error}");
    }

    #[test]
    fn reports_placeholders_as_not_implemented() {
        let error = Upstream::parse_dial("{env.UPSTREAM}", false).unwrap_err();
        assert!(error.contains("placeholders"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn parses_unix_dial_forms() {
        let canonical = Upstream::parse_dial("unix//run/app.sock", false).unwrap();
        let relative = Upstream::parse_dial("unix/run/app.sock", false).unwrap();
        assert_eq!(
            canonical.transport(),
            &Transport::Unix {
                path: PathBuf::from("/run/app.sock")
            }
        );
        assert_eq!(
            relative.transport(),
            &Transport::Unix {
                path: PathBuf::from("run/app.sock")
            }
        );
        assert_eq!(canonical.fallback_host(), "localhost");
        let url = canonical.url("/health");
        assert!(url.starts_with("unix://"), "{url}");
        assert!(url.ends_with("/health"), "{url}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_authority_round_trips_socket_paths() {
        for path in ["/run/app.sock", "/tmp/日本語.sock", "relative.sock"] {
            let encoded = encode_unix_authority(std::path::Path::new(path));
            assert!(
                encoded.chars().all(|ch| ch.is_ascii_hexdigit()),
                "{encoded}"
            );
            let decoded = decode_unix_authority(&encoded).unwrap();
            assert_eq!(decoded, PathBuf::from(path));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unix_dial_without_path() {
        for dial in ["unix", "unix/"] {
            let error = Upstream::parse_dial(dial, false).unwrap_err();
            assert!(error.contains("missing a socket path"), "{error}");
        }
    }

    #[test]
    fn connection_guard_tracks_in_flight_requests() {
        let upstream = Upstream::new("localhost:1", false);
        {
            let _guard = upstream.connection_started();
            assert_eq!(upstream.active_connections(), 1);
        }
        assert_eq!(upstream.active_connections(), 0);
    }
}
