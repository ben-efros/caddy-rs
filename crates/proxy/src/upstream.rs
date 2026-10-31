//! Upstream server representation and dial parsing.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A proxy upstream.
#[derive(Debug)]
pub struct Upstream {
    /// Dial address (`host:port`).
    pub dial: String,
    /// Whether this upstream TLS is required.
    pub tls: bool,
    healthy: AtomicBool,
    active_connections: AtomicUsize,
}

impl Upstream {
    /// Construct an upstream.
    pub fn new(dial: impl Into<String>, tls: bool) -> Self {
        Self {
            dial: dial.into(),
            tls,
            healthy: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
        }
    }

    /// Parse a Caddy `dial` value.
    pub fn parse_dial(dial: &str, tls: bool) -> Result<Self, String> {
        if dial.is_empty() {
            return Err("upstream dial address is empty".to_string());
        }
        if dial.contains('{') {
            return Err(format!(
                "upstream `{dial}` uses placeholders, which are not implemented (HTTP-PLACEHOLDERS)"
            ));
        }
        if dial.starts_with("unix/") {
            return Err(format!(
                "unix socket upstream `{dial}` is not implemented yet (PROXY-UNIX)"
            ));
        }
        if dial.starts_with("http://") || dial.starts_with("https://") {
            return Err(format!("upstream dial `{dial}` must not include a scheme"));
        }
        if !dial.contains(':') {
            return Err(format!("upstream dial `{dial}` is missing a port"));
        }
        Ok(Self::new(dial, tls))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port_dial() {
        let upstream = Upstream::parse_dial("localhost:8096", false).unwrap();
        assert_eq!(upstream.dial, "localhost:8096");
        assert!(upstream.is_healthy());
    }

    #[test]
    fn rejects_scheme_and_missing_port() {
        assert!(Upstream::parse_dial("http://localhost:8096", false).is_err());
        assert!(Upstream::parse_dial("localhost", false).is_err());
    }

    #[test]
    fn reports_placeholders_and_unix_as_not_implemented() {
        let error = Upstream::parse_dial("{env.UPSTREAM}", false).unwrap_err();
        assert!(error.contains("placeholders"), "{error}");
        let error = Upstream::parse_dial("unix//run/app.sock", false).unwrap_err();
        assert!(error.contains("unix"), "{error}");
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
