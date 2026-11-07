//! Caddy dynamic upstream modules (`http.reverse_proxy.upstreams.*`).
//!
//! Caddy v2.11.9 `modules/caddyhttp/reverseproxy/upstreams.go`:
//!
//! * `srv` — RFC 2782 SRV lookups (`_service._proto.name` or a bare `name`); records sorted by
//!   priority and weighted within a priority (Go's resolver ordering); results cached for
//!   `refresh` (default 1m) and kept for `grace_period` when a lookup fails; optional custom
//!   resolvers and `dial_network` prefix.
//! * `a` — A/AAAA lookups of `name`, dialled with `port` (default 80) and optional `versions`
//!   filtering (`ip4`/`ip6`/`ip`); results cached for `refresh`; no grace period.
//! * `multi` — queries each source in order and appends the results; per-source errors are logged
//!   and skipped, and empty sources contribute nothing. Caddy does not deduplicate or sort the
//!   merged list.
//!
//! Sources return upstream dial addresses; the proxy handler provisions them into its dynamic-host
//! registry and feeds the normal balancing/retry machinery. The `DnsResolver` trait is injectable
//! so tests (and other embedders) can supply a fake resolver; production uses
//! [`crate::dns::SystemDnsResolver`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::Value;

use caddy_rs_http::{Error as HttpError, Request, Result as HttpResult};

use crate::dns::{order_srv_records, DnsResolver, IpVersion, ResolverAddress, SystemDnsResolver};

/// Caddy's default refresh interval for SRV/A sources.
const DEFAULT_REFRESH: Duration = Duration::from_secs(60);
/// Bound every DNS lookup even when Caddy would rely on the request context.
const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Caddy evicts an arbitrary cache entry once a source cache reaches this many keys.
const MAX_CACHE_ENTRIES: usize = 100;

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

fn not_implemented(feature: &'static str, tracking_id: &'static str) -> HttpError {
    HttpError::NotImplemented {
        feature,
        tracking_id,
    }
}

/// One dynamic upstream source: yields dial addresses for a request.
///
/// Implementations cache lookups internally (Caddy's `UpstreamSource`); the proxy handler calls
/// this once per proxy-loop iteration and on retries calls [`reset_cache`](Self::reset_cache) so a
/// failed backend can be re-resolved (Caddy's `CachingUpstreamSource`).
#[async_trait]
pub trait DynamicUpstreamSource: Send + Sync + std::fmt::Debug {
    /// Upstream dial addresses (`host:port`, `[v6]:port`) in provider order.
    async fn get_upstreams(&self, request: &Request) -> Result<Vec<String>, String>;

    /// Drop cached entries related to `request` (used before retries).
    fn reset_cache(&self, request: &Request);

    /// Human-readable description for logs and errors.
    fn describe(&self) -> String;
}

/// Parsed `dynamic_upstreams` configuration (the three built-in Caddy source modules).
#[derive(Debug)]
pub enum DynamicUpstreams {
    /// SRV lookup source.
    Srv(SrvUpstreams),
    /// A/AAAA lookup source.
    A(AUpstreams),
    /// Ordered aggregation of other sources.
    Multi(MultiUpstreams),
}

impl DynamicUpstreams {
    /// Parse `dynamic_upstreams` using the system DNS resolver.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        Self::from_json_with_resolver(value, path, Arc::new(SystemDnsResolver))
    }

    /// Parse `dynamic_upstreams` with an injected resolver (tests/embedders).
    pub fn from_json_with_resolver(
        value: &Value,
        path: &str,
        resolver: Arc<dyn DnsResolver>,
    ) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`dynamic_upstreams` must be an object"))?;
        let source = object
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid(
                    path,
                    "`dynamic_upstreams` requires a `source` string (`srv`, `a` or `multi`)",
                )
            })?;
        match source {
            "srv" => Ok(Self::Srv(SrvUpstreams::from_json(value, path, resolver)?)),
            "a" => Ok(Self::A(AUpstreams::from_json(value, path, resolver)?)),
            "multi" => Ok(Self::Multi(MultiUpstreams::from_json(
                value, path, resolver,
            )?)),
            _ => Err(not_implemented(
                "dynamic upstream source modules other than srv/a/multi",
                "DYNAMIC-UPSTREAM-SOURCE",
            )),
        }
    }
}

#[async_trait]
impl DynamicUpstreamSource for DynamicUpstreams {
    async fn get_upstreams(&self, request: &Request) -> Result<Vec<String>, String> {
        match self {
            Self::Srv(source) => source.get_upstreams(request).await,
            Self::A(source) => source.get_upstreams(request).await,
            Self::Multi(source) => source.get_upstreams(request).await,
        }
    }

    fn reset_cache(&self, request: &Request) {
        match self {
            Self::Srv(source) => source.reset_cache(request),
            Self::A(source) => source.reset_cache(request),
            Self::Multi(source) => source.reset_cache(request),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Srv(source) => source.describe(),
            Self::A(source) => source.describe(),
            Self::Multi(source) => source.describe(),
        }
    }
}

/// One cache entry per expanded lookup key (Caddy's global `srvs`/`aAaaa` maps).
#[derive(Debug, Default)]
struct SourceCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    /// Deterministic eviction order: insertion sequence per key.
    order: Mutex<Vec<String>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    fresh_until: Instant,
    upstreams: Vec<String>,
}

impl SourceCache {
    fn fresh_upstreams(&self, key: &str) -> Option<Vec<String>> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries
            .get(key)
            .filter(|entry| Instant::now() < entry.fresh_until)
            .map(|entry| entry.upstreams.clone())
    }

    fn any_upstreams(&self, key: &str) -> Option<Vec<String>> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.get(key).map(|entry| entry.upstreams.clone())
    }

    fn store(&self, key: String, upstreams: Vec<String>, fresh_for: Duration) {
        {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !entries.contains_key(&key) && entries.len() >= MAX_CACHE_ENTRIES {
                let mut order = self
                    .order
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(victim) = order.first().cloned() {
                    entries.remove(&victim);
                    order.remove(0);
                }
            }
            entries.insert(
                key.clone(),
                CacheEntry {
                    fresh_until: Instant::now() + fresh_for,
                    upstreams,
                },
            );
        }
        let mut order = self
            .order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !order.iter().any(|existing| existing == &key) {
            order.push(key);
        }
    }

    fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    fn remove(&self, key: &str) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
        self.order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|existing| existing != key);
    }
}

/// SRV record source (Caddy `SRVUpstreams`).
#[derive(Debug)]
pub struct SrvUpstreams {
    service: String,
    proto: String,
    name: String,
    refresh: Duration,
    grace_period: Duration,
    resolvers: Vec<ResolverAddress>,
    lookup_timeout: Duration,
    resolver: Arc<dyn DnsResolver>,
    cache: SourceCache,
}

impl SrvUpstreams {
    fn from_json(value: &Value, path: &str, resolver: Arc<dyn DnsResolver>) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`srv` dynamic upstream must be an object"))?;
        reject_unknown(
            object,
            path,
            &[
                "source",
                "service",
                "proto",
                "name",
                "refresh",
                "grace_period",
                "resolver",
                "dial_timeout",
                "dial_fallback_delay",
                "dial_network",
            ],
        )?;
        let service = optional_string(object, "service", path)?.unwrap_or_default();
        let proto = optional_string(object, "proto", path)?.unwrap_or_default();
        let name = optional_string(object, "name", path)?
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid(&format!("{path}.name"), "`name` is required for `srv`"))?;
        if !service.is_empty() && proto.is_empty() {
            return Err(invalid(
                &format!("{path}.proto"),
                "`proto` is required when `service` is set",
            ));
        }
        if service.is_empty() && !proto.is_empty() {
            return Err(invalid(
                &format!("{path}.service"),
                "`service` is required when `proto` is set",
            ));
        }
        if !proto.is_empty() && !matches!(proto.as_str(), "tcp" | "udp") {
            return Err(invalid(
                &format!("{path}.proto"),
                "`proto` must be `tcp` or `udp`",
            ));
        }
        let refresh = parse_refresh(object, path)?;
        let grace_period = parse_duration(object, "grace_period", path)?;
        let resolvers = parse_resolver(object, path)?;
        let lookup_timeout = parse_dial_timeout(object, path)?;
        reject_fallback_delay(object, path)?;
        reject_dial_network(object, path)?;
        Ok(Self {
            service,
            proto,
            name,
            refresh,
            grace_period,
            resolvers,
            lookup_timeout,
            resolver,
            cache: SourceCache::default(),
        })
    }

    fn expanded_target(&self, request: &Request) -> String {
        let name = request.replace_all(&self.name);
        let service = request.replace_all(&self.service);
        let proto = request.replace_all(&self.proto);
        if service.is_empty() && proto.is_empty() {
            name
        } else {
            format!("_{service}._{proto}.{name}")
        }
    }

    async fn get_upstreams(&self, request: &Request) -> Result<Vec<String>, String> {
        let target = self.expanded_target(request);
        if target.is_empty() {
            return Err("SRV lookup name is empty after placeholder expansion".to_string());
        }
        if let Some(upstreams) = self.cache.fresh_upstreams(&target) {
            return Ok(upstreams);
        }
        let lookup = self
            .resolver
            .lookup_srv(&target, &self.resolvers, self.lookup_timeout)
            .await;
        match lookup {
            Ok(mut records) => {
                order_srv_records(&mut records);
                let upstreams: Vec<String> = records
                    .iter()
                    .map(|record| format_dial(&record.target, record.port))
                    .collect();
                self.cache.store(target, upstreams.clone(), self.refresh);
                Ok(upstreams)
            }
            Err(error) => {
                // Caddy's `grace_period`: serve the last-known-good set while retrying.
                if self.grace_period > Duration::ZERO {
                    if let Some(upstreams) = self.cache.any_upstreams(&target) {
                        self.cache
                            .store(target, upstreams.clone(), self.grace_period);
                        return Ok(upstreams);
                    }
                }
                Err(format!("SRV lookup for `{target}` failed: {error}"))
            }
        }
    }

    fn reset_cache(&self, request: &Request) {
        self.cache.remove(&self.expanded_target(request));
    }

    fn describe(&self) -> String {
        if self.service.is_empty() && self.proto.is_empty() {
            format!("srv {}", self.name)
        } else {
            format!("srv _{}_.{}.{}", self.service, self.proto, self.name)
        }
    }
}

/// A/AAAA record source (Caddy `AUpstreams`).
#[derive(Debug)]
pub struct AUpstreams {
    name: String,
    port: String,
    refresh: Duration,
    version: IpVersion,
    version_key: &'static str,
    resolvers: Vec<ResolverAddress>,
    lookup_timeout: Duration,
    resolver: Arc<dyn DnsResolver>,
    cache: SourceCache,
}

impl AUpstreams {
    fn from_json(value: &Value, path: &str, resolver: Arc<dyn DnsResolver>) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`a` dynamic upstream must be an object"))?;
        reject_unknown(
            object,
            path,
            &[
                "source",
                "name",
                "port",
                "refresh",
                "versions",
                "resolver",
                "dial_timeout",
                "dial_fallback_delay",
            ],
        )?;
        let name = optional_string(object, "name", path)?
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid(&format!("{path}.name"), "`name` is required for `a`"))?;
        let port = optional_string(object, "port", path)?.unwrap_or_else(|| "80".to_string());
        if !port.contains('{') {
            port.parse::<u16>().map_err(|_| {
                invalid(
                    &format!("{path}.port"),
                    "`port` must be a TCP port number (0-65535) or a placeholder",
                )
            })?;
        }
        let refresh = parse_refresh(object, path)?;
        let (version, version_key) = parse_versions(object, path)?;
        let resolvers = parse_resolver(object, path)?;
        let lookup_timeout = parse_dial_timeout(object, path)?;
        reject_fallback_delay(object, path)?;
        Ok(Self {
            name,
            port,
            refresh,
            version,
            version_key,
            resolvers,
            lookup_timeout,
            resolver,
            cache: SourceCache::default(),
        })
    }

    async fn get_upstreams(&self, request: &Request) -> Result<Vec<String>, String> {
        let name = request.replace_all(&self.name);
        let port = request.replace_all(&self.port);
        if name.is_empty() {
            return Err("A/AAAA lookup name is empty after placeholder expansion".to_string());
        }
        let port_number: u16 = port
            .parse()
            .map_err(|_| format!("A/AAAA upstream port `{port}` is not a valid TCP port"))?;
        let key = format!("{name}:{port_number}:{}", self.version_key);
        if let Some(upstreams) = self.cache.fresh_upstreams(&key) {
            return Ok(upstreams);
        }
        let lookup = self
            .resolver
            .lookup_ip(&name, self.version, &self.resolvers, self.lookup_timeout)
            .await;
        match lookup {
            Ok(addresses) => {
                let upstreams: Vec<String> = addresses
                    .iter()
                    .map(|address| format_dial(&address.to_string(), port_number))
                    .collect();
                self.cache.store(key, upstreams.clone(), self.refresh);
                Ok(upstreams)
            }
            Err(error) => Err(format!("A/AAAA lookup for `{name}` failed: {error}")),
        }
    }

    fn reset_cache(&self, request: &Request) {
        let name = request.replace_all(&self.name);
        let port = request.replace_all(&self.port);
        // Clear every entry for this name/version; keys also include the expanded port.
        self.cache.clear();
        let _ = (name, port);
    }

    fn describe(&self) -> String {
        format!("a {}:{}", self.name, self.port)
    }
}

/// Aggregated source (Caddy `MultiUpstreams`).
#[derive(Debug)]
pub struct MultiUpstreams {
    sources: Vec<Arc<DynamicUpstreams>>,
}

impl MultiUpstreams {
    fn from_json(value: &Value, path: &str, resolver: Arc<dyn DnsResolver>) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`multi` dynamic upstream must be an object"))?;
        reject_unknown(object, path, &["source", "sources"])?;
        let sources = match object.get("sources") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => {
                let sources = value.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{path}.sources"),
                        "`sources` must be an array of dynamic upstream source objects",
                    )
                })?;
                let mut parsed = Vec::with_capacity(sources.len());
                for (index, source) in sources.iter().enumerate() {
                    let source_path = format!("{path}.sources[{index}]");
                    parsed.push(Arc::new(DynamicUpstreams::from_json_with_resolver(
                        source,
                        &source_path,
                        Arc::clone(&resolver),
                    )?));
                }
                parsed
            }
        };
        Ok(Self { sources })
    }

    async fn get_upstreams(&self, request: &Request) -> Result<Vec<String>, String> {
        let mut upstreams = Vec::new();
        for (index, source) in self.sources.iter().enumerate() {
            match source.get_upstreams(request).await {
                Ok(mut found) => {
                    if found.is_empty() {
                        eprintln!(
                            "caddy-rs: dynamic upstream source[{index}] `{}` returned 0 upstreams",
                            source.describe()
                        );
                    } else {
                        upstreams.append(&mut found);
                    }
                }
                Err(error) => {
                    // Caddy logs per-source errors and keeps going; `multi` itself never fails.
                    eprintln!(
                        "caddy-rs: dynamic upstream source[{index}] `{}` failed: {error}",
                        source.describe()
                    );
                }
            }
        }
        Ok(upstreams)
    }

    fn reset_cache(&self, request: &Request) {
        for source in &self.sources {
            source.reset_cache(request);
        }
    }

    fn describe(&self) -> String {
        let described: Vec<String> = self
            .sources
            .iter()
            .map(|source| source.describe())
            .collect();
        format!("multi [{}]", described.join(", "))
    }
}

/// Format a dial address, bracketing IPv6 hosts like Go's `net.JoinHostPort`.
fn format_dial(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn reject_unknown(
    object: &serde_json::Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> HttpResult<()> {
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(invalid(
                path,
                format!("unknown dynamic upstream field `{field}`"),
            ));
        }
    }
    Ok(())
}

fn optional_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    path: &str,
) -> HttpResult<Option<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(
            &format!("{path}.{field}"),
            format!("`{field}` must be a string"),
        )),
    }
}

fn parse_duration(
    object: &serde_json::Map<String, Value>,
    field: &str,
    path: &str,
) -> HttpResult<Duration> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(Duration::ZERO),
        Some(value) => {
            let nanos = value.as_u64().ok_or_else(|| {
                invalid(
                    &format!("{path}.{field}"),
                    format!("`{field}` must be a non-negative duration in nanoseconds"),
                )
            })?;
            Ok(Duration::from_nanos(nanos))
        }
    }
}

fn parse_refresh(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<Duration> {
    let refresh = parse_duration(object, "refresh", path)?;
    Ok(if refresh.is_zero() {
        DEFAULT_REFRESH
    } else {
        refresh
    })
}

fn parse_resolver(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<Vec<ResolverAddress>> {
    let Some(value) = object.get("resolver") else {
        return Ok(Vec::new());
    };
    let path = format!("{path}.resolver");
    let resolver = value
        .as_object()
        .ok_or_else(|| invalid(&path, "`resolver` must be an object"))?;
    for field in resolver.keys() {
        if field != "addresses" {
            return Err(invalid(&path, format!("unknown resolver field `{field}`")));
        }
    }
    let addresses = resolver
        .get("addresses")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{path}.addresses"), "`addresses` is required"))?;
    if addresses.is_empty() {
        return Err(invalid(
            &format!("{path}.addresses"),
            "`addresses` must contain at least one DNS resolver address",
        ));
    }
    let mut parsed = Vec::with_capacity(addresses.len());
    for (index, address) in addresses.iter().enumerate() {
        let address = address.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}.addresses[{index}]"),
                "resolver addresses must be strings",
            )
        })?;
        parsed.push(
            ResolverAddress::parse(address)
                .map_err(|error| invalid(&format!("{path}.addresses[{index}]"), error))?,
        );
    }
    Ok(parsed)
}

fn parse_dial_timeout(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<Duration> {
    let timeout = parse_duration(object, "dial_timeout", path)?;
    Ok(if timeout.is_zero() {
        DEFAULT_LOOKUP_TIMEOUT
    } else {
        timeout
    })
}

fn reject_fallback_delay(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<()> {
    if let Some(value) = object.get("dial_fallback_delay") {
        let delay = value.as_i64().ok_or_else(|| {
            invalid(
                &format!("{path}.dial_fallback_delay"),
                "`dial_fallback_delay` must be a number",
            )
        })?;
        if delay != 0 {
            return Err(not_implemented(
                "dynamic upstream resolver fallback delay",
                "DYNAMIC-UPSTREAM-FALLBACK-DELAY",
            ));
        }
    }
    Ok(())
}

fn reject_dial_network(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<()> {
    if let Some(value) = object.get("dial_network") {
        let network = value.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}.dial_network"),
                "`dial_network` must be a string",
            )
        })?;
        if !network.is_empty() && network != "tcp" {
            return Err(not_implemented(
                "dynamic upstream `dial_network` restrictions (tcp4/tcp6)",
                "DYNAMIC-UPSTREAM-DIAL-NETWORK",
            ));
        }
    }
    Ok(())
}

/// Caddy's `resolveIpVersion`: both fields absent → both families; only v4/v6 enabled selects that
/// family; Caddy's implementation falls back to `ip` when both are explicitly false.
fn parse_versions(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<(IpVersion, &'static str)> {
    let Some(value) = object.get("versions") else {
        return Ok((IpVersion::Both, "ip"));
    };
    let path = format!("{path}.versions");
    let versions = value
        .as_object()
        .ok_or_else(|| invalid(&path, "`versions` must be an object"))?;
    for field in versions.keys() {
        if field != "ipv4" && field != "ipv6" {
            return Err(invalid(
                &path,
                format!("unknown `versions` field `{field}`"),
            ));
        }
    }
    let ipv4 = versions.get("ipv4").and_then(Value::as_bool);
    let ipv6 = versions.get("ipv6").and_then(Value::as_bool);
    if ipv4.is_none() && ipv6.is_none() {
        return Ok((IpVersion::Both, "ip"));
    }
    let resolve_v4 = ipv4.unwrap_or(false);
    let resolve_v6 = ipv6.unwrap_or(false);
    match (resolve_v4, resolve_v6) {
        (true, false) => Ok((IpVersion::V4Only, "ip4")),
        (false, true) => Ok((IpVersion::V6Only, "ip6")),
        // Caddy's resolveIpVersion returns "ip" here (both false included).
        _ => Ok((IpVersion::Both, "ip")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct FakeResolver {
        ip: Mutex<VecDeque<Result<Vec<std::net::IpAddr>, String>>>,
        srv: Mutex<VecDeque<Result<Vec<crate::dns::SrvRecord>, String>>>,
        lookups: AtomicUsize,
        last_name: Mutex<Option<String>>,
        last_version: Mutex<Option<IpVersion>>,
    }

    impl FakeResolver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                ip: Mutex::new(VecDeque::new()),
                srv: Mutex::new(VecDeque::new()),
                lookups: AtomicUsize::new(0),
                last_name: Mutex::new(None),
                last_version: Mutex::new(None),
            })
        }

        fn push_ip(&self, result: Result<Vec<std::net::IpAddr>, String>) {
            self.ip.lock().unwrap().push_back(result);
        }

        fn push_srv(&self, result: Result<Vec<crate::dns::SrvRecord>, String>) {
            self.srv.lock().unwrap().push_back(result);
        }

        fn lookups(&self) -> usize {
            self.lookups.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DnsResolver for FakeResolver {
        async fn lookup_ip(
            &self,
            name: &str,
            version: IpVersion,
            _resolvers: &[ResolverAddress],
            _timeout: Duration,
        ) -> Result<Vec<std::net::IpAddr>, String> {
            self.lookups
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_name.lock().unwrap() = Some(name.to_string());
            *self.last_version.lock().unwrap() = Some(version);
            self.ip
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err("fake resolver has no scripted IP result".to_string()))
        }

        async fn lookup_srv(
            &self,
            name: &str,
            _resolvers: &[ResolverAddress],
            _timeout: Duration,
        ) -> Result<Vec<crate::dns::SrvRecord>, String> {
            self.lookups
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_name.lock().unwrap() = Some(name.to_string());
            self.srv
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err("fake resolver has no scripted SRV result".to_string()))
        }
    }

    fn request() -> Request {
        Request::new(http::Method::GET, "/".parse().unwrap())
    }

    fn source(value: serde_json::Value, resolver: Arc<FakeResolver>) -> DynamicUpstreams {
        DynamicUpstreams::from_json_with_resolver(&value, "dynamic_upstreams", resolver)
            .expect("dynamic upstream config builds")
    }

    fn srv_record(target: &str, port: u16, priority: u16, weight: u16) -> crate::dns::SrvRecord {
        crate::dns::SrvRecord {
            target: target.to_string(),
            port,
            priority,
            weight,
        }
    }

    async fn upstreams(source: &DynamicUpstreams) -> Vec<String> {
        source
            .get_upstreams(&request())
            .await
            .expect("lookup succeeds")
    }

    #[tokio::test]
    async fn srv_source_orders_priority_and_formats_dials() {
        let resolver = FakeResolver::new();
        resolver.push_srv(Ok(vec![
            srv_record("second.example", 9000, 20, 10),
            srv_record("first.example", 8080, 10, 1),
            srv_record("third.example", 8081, 10, 100),
        ]));
        let source = source(
            serde_json::json!({"source": "srv", "service": "http", "proto": "tcp",
                "name": "example.com"}),
            Arc::clone(&resolver),
        );
        let dials = upstreams(&source).await;
        assert_eq!(dials.len(), 3);
        assert_eq!(
            dials.last().map(String::as_str),
            Some("second.example:9000"),
            "higher priority number sorts last: {dials:?}"
        );
        let mut low: Vec<&str> = dials[..2].iter().map(String::as_str).collect();
        low.sort_unstable();
        assert_eq!(low, vec!["first.example:8080", "third.example:8081"]);
        assert_eq!(
            resolver.last_name.lock().unwrap().as_deref(),
            Some("_http._tcp.example.com")
        );
    }

    #[tokio::test]
    async fn srv_source_keeps_last_good_set_during_grace_period() {
        let resolver = FakeResolver::new();
        resolver.push_srv(Ok(vec![srv_record("good.example", 8080, 10, 1)]));
        let with_grace = source(
            serde_json::json!({"source": "srv", "name": "example.com",
                "refresh": 1u64, "grace_period": 60_000_000_000u64}),
            Arc::clone(&resolver),
        );
        assert_eq!(upstreams(&with_grace).await, vec!["good.example:8080"]);
        std::thread::sleep(Duration::from_millis(5));
        resolver.push_srv(Err("dns down".to_string()));
        assert_eq!(
            upstreams(&with_grace).await,
            vec!["good.example:8080"],
            "grace period serves the stale last-known-good set"
        );

        // Without a grace period the lookup error is surfaced to the handler (static fallback).
        let resolver = FakeResolver::new();
        resolver.push_srv(Ok(vec![srv_record("good.example", 8080, 10, 1)]));
        let strict = source(
            serde_json::json!({"source": "srv", "name": "example.com", "refresh": 1u64}),
            Arc::clone(&resolver),
        );
        assert_eq!(upstreams(&strict).await, vec!["good.example:8080"]);
        std::thread::sleep(Duration::from_millis(5));
        resolver.push_srv(Err("dns down".to_string()));
        let error = strict
            .get_upstreams(&request())
            .await
            .expect_err("no grace period means the error is returned");
        assert!(error.contains("dns down"), "{error}");
    }

    #[tokio::test]
    async fn a_source_expands_versions_port_and_refreshes() {
        let resolver = FakeResolver::new();
        resolver.push_ip(Ok(vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]));
        resolver.push_ip(Ok(vec!["192.0.2.20".parse().unwrap()]));
        let source = source(
            serde_json::json!({"source": "a", "name": "backend.example", "port": "8080",
                "refresh": 50_000_000u64}),
            Arc::clone(&resolver),
        );
        let dials = upstreams(&source).await;
        assert_eq!(
            dials,
            vec![
                "192.0.2.10:8080".to_string(),
                "[2001:db8::1]:8080".to_string()
            ]
        );
        assert_eq!(
            *resolver.last_version.lock().unwrap(),
            Some(IpVersion::Both)
        );

        // Fresh cache: no second lookup.
        assert_eq!(upstreams(&source).await.len(), 2);
        assert_eq!(resolver.lookups(), 1);

        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(upstreams(&source).await, vec!["192.0.2.20:8080"]);
        assert_eq!(resolver.lookups(), 2);
    }

    #[tokio::test]
    async fn a_source_versions_selects_the_family() {
        let resolver = FakeResolver::new();
        resolver.push_ip(Ok(vec!["192.0.2.10".parse().unwrap()]));
        let ipv4 = source(
            serde_json::json!({"source": "a", "name": "backend.example",
                "versions": {"ipv4": true, "ipv6": false}}),
            Arc::clone(&resolver),
        );
        assert_eq!(upstreams(&ipv4).await, vec!["192.0.2.10:80"]);
        assert_eq!(
            *resolver.last_version.lock().unwrap(),
            Some(IpVersion::V4Only)
        );

        let ipv6 = source(
            serde_json::json!({"source": "a", "name": "backend.example",
                "versions": {"ipv4": false, "ipv6": true}}),
            Arc::clone(&resolver),
        );
        resolver.push_ip(Ok(vec!["2001:db8::1".parse().unwrap()]));
        assert_eq!(upstreams(&ipv6).await, vec!["[2001:db8::1]:80"]);
        assert_eq!(
            *resolver.last_version.lock().unwrap(),
            Some(IpVersion::V6Only)
        );
    }

    #[tokio::test]
    async fn a_source_rejects_invalid_expanded_port_and_empty_results() {
        let resolver = FakeResolver::new();
        resolver.push_ip(Ok(Vec::new()));
        let source = source(
            serde_json::json!({"source": "a", "name": "backend.example", "port": "{http.vars.port}"}),
            Arc::clone(&resolver),
        );
        let mut request = request();
        request
            .vars
            .insert("port".to_string(), "not-a-port".to_string());
        let error = source
            .get_upstreams(&request)
            .await
            .expect_err("invalid expanded port fails");
        assert!(error.contains("not a valid TCP port"), "{error}");

        request.vars.insert("port".to_string(), "8080".to_string());
        assert_eq!(
            source.get_upstreams(&request).await.unwrap(),
            Vec::<String>::new(),
            "an empty A result is a successful empty pool (handler then 503s)"
        );
    }

    #[tokio::test]
    async fn multi_appends_in_order_and_skips_failing_sources() {
        let resolver = FakeResolver::new();
        resolver.push_ip(Err("first source down".to_string()));
        resolver.push_ip(Ok(vec!["192.0.2.20".parse().unwrap()]));
        let multi = source(
            serde_json::json!({"source": "multi", "sources": [
                {"source": "a", "name": "one.example"},
                {"source": "a", "name": "two.example", "port": "8080"}
            ]}),
            Arc::clone(&resolver),
        );
        // First source errors (logged/skipped); the second's results are appended in order.
        assert_eq!(upstreams(&multi).await, vec!["192.0.2.20:8080"]);
    }

    #[tokio::test]
    async fn multi_concatenates_without_deduplication() {
        let resolver = FakeResolver::new();
        resolver.push_ip(Ok(vec!["192.0.2.10".parse().unwrap()]));
        resolver.push_ip(Ok(vec!["192.0.2.10".parse().unwrap()]));
        let multi = source(
            serde_json::json!({"source": "multi", "sources": [
                {"source": "a", "name": "one.example"},
                {"source": "a", "name": "two.example"}
            ]}),
            Arc::clone(&resolver),
        );
        assert_eq!(
            upstreams(&multi).await,
            vec!["192.0.2.10:80".to_string(), "192.0.2.10:80".to_string()],
            "Caddy's multi appends both sources without deduplication"
        );
    }

    #[tokio::test]
    async fn reset_cache_forces_a_new_lookup() {
        let resolver = FakeResolver::new();
        resolver.push_srv(Ok(vec![srv_record("one.example", 8080, 10, 1)]));
        resolver.push_srv(Ok(vec![srv_record("two.example", 8080, 10, 1)]));
        let source = source(
            serde_json::json!({"source": "srv", "name": "example.com"}),
            Arc::clone(&resolver),
        );
        assert_eq!(upstreams(&source).await, vec!["one.example:8080"]);
        source.reset_cache(&request());
        assert_eq!(upstreams(&source).await, vec!["two.example:8080"]);
        assert_eq!(resolver.lookups(), 2);
    }

    #[test]
    fn resolver_addresses_parse_network_and_default_port() {
        assert_eq!(
            ResolverAddress::parse("1.1.1.1").unwrap().address,
            "1.1.1.1:53".parse().unwrap()
        );
        assert_eq!(
            ResolverAddress::parse("tcp/8.8.8.8:5353").unwrap().network,
            crate::dns::ResolverNetwork::Tcp
        );
        assert!(ResolverAddress::parse("resolver.example:53").is_err());
        assert!(ResolverAddress::parse("sctp/1.1.1.1").is_err());
    }

    #[test]
    fn srv_and_a_configuration_validation_is_located() {
        let resolver = FakeResolver::new();
        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": ""}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("empty name fails");
        assert!(
            error.to_string().contains("dynamic_upstreams.name"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": "example.com", "port": "http"}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("invalid port fails");
        assert!(
            error.to_string().contains("dynamic_upstreams.port"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": "example.com", "unknown": true}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("unknown field fails");
        assert!(
            error.to_string().contains("unknown dynamic upstream field"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "srv", "service": "http", "name": "example.com"}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("service without proto fails");
        assert!(
            error.to_string().contains("dynamic_upstreams.proto"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": "example.com", "max_answers": 2}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("max_answers is not a Caddy field");
        assert!(
            error.to_string().contains("unknown dynamic upstream field"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "magic"}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("unknown source fails");
        assert!(
            error.to_string().contains("DYNAMIC-UPSTREAM-SOURCE"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": "example.com",
                "dial_fallback_delay": 1000}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("fallback delay is unsupported");
        assert!(
            error
                .to_string()
                .contains("DYNAMIC-UPSTREAM-FALLBACK-DELAY"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "srv", "name": "example.com", "dial_network": "tcp4"}),
            "dynamic_upstreams",
            Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        )
        .expect_err("dial_network is unsupported");
        assert!(
            error.to_string().contains("DYNAMIC-UPSTREAM-DIAL-NETWORK"),
            "{error}"
        );

        let error = DynamicUpstreams::from_json_with_resolver(
            &serde_json::json!({"source": "a", "name": "example.com",
                "resolver": {"addresses": ["not-an-ip"]}}),
            "dynamic_upstreams",
            resolver as Arc<dyn DnsResolver>,
        )
        .expect_err("invalid resolver address fails");
        assert!(
            error
                .to_string()
                .contains("dynamic_upstreams.resolver.addresses[0]"),
            "{error}"
        );
    }
}
