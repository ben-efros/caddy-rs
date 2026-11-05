//! Upstream selection policies.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use caddy_rs_http::Request;

use crate::upstream::Upstream;

/// A load-balancing policy.
pub trait Balancer: Send + Sync {
    /// Policy name as it appears in Caddy configuration.
    fn name(&self) -> &'static str;

    /// Choose an upstream, considering only healthy ones.
    fn select(&self, upstreams: &[Arc<Upstream>], request: &Request) -> Option<Arc<Upstream>>;
}

/// A load-balancing policy configuration error.
#[derive(Debug)]
pub enum BalancerError {
    /// The policy JSON is invalid for the selected policy.
    Invalid(String),
    /// The policy is not implemented by this build.
    NotImplemented {
        /// Human-readable feature name.
        feature: &'static str,
        /// Tracking id for the compatibility matrix.
        tracking_id: &'static str,
    },
}

impl std::fmt::Display for BalancerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::NotImplemented { feature, .. } => {
                write!(formatter, "{feature} is not implemented by this build")
            }
        }
    }
}

/// `first`: always the first healthy upstream.
pub struct First;

impl Balancer for First {
    fn name(&self) -> &'static str {
        "first"
    }

    fn select(&self, upstreams: &[Arc<Upstream>], _request: &Request) -> Option<Arc<Upstream>> {
        upstreams.iter().find(|u| u.is_healthy()).cloned()
    }
}

/// `round_robin`: rotate through healthy upstreams.
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    /// Create a round-robin balancer.
    pub fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer for RoundRobin {
    fn name(&self) -> &'static str {
        "round_robin"
    }

    fn select(&self, upstreams: &[Arc<Upstream>], _request: &Request) -> Option<Arc<Upstream>> {
        if upstreams.is_empty() {
            return None;
        }
        for _ in 0..upstreams.len() {
            let index = self.next.fetch_add(1, Ordering::AcqRel) % upstreams.len();
            let upstream = &upstreams[index];
            if upstream.is_healthy() {
                return Some(Arc::clone(upstream));
            }
        }
        None
    }
}

/// `least_conn`: fewest in-flight requests.
pub struct LeastConnections;

impl Balancer for LeastConnections {
    fn name(&self) -> &'static str {
        "least_conn"
    }

    fn select(&self, upstreams: &[Arc<Upstream>], _request: &Request) -> Option<Arc<Upstream>> {
        upstreams
            .iter()
            .filter(|upstream| upstream.is_healthy())
            .min_by_key(|upstream| upstream.active_connections())
            .cloned()
    }
}

/// `random`: choose a healthy upstream uniformly at random (Caddy's default policy).
pub struct Random {
    state: AtomicU64,
}

impl Random {
    /// Create a random balancer seeded from the clock.
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x9E37_79B1_85EB_CA87)
            ^ 0x9E37_79B1_85EB_CA87;
        Self::with_seed(seed)
    }

    /// Create a random balancer with a fixed seed (deterministic tests).
    pub fn with_seed(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed),
        }
    }

    /// SplitMix64 step.
    fn next_u64(&self) -> u64 {
        self.state
            .fetch_add(0x9E37_79B1_85EB_CA87, Ordering::Relaxed);
        let mut z = self.state.load(Ordering::Relaxed);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer for Random {
    fn name(&self) -> &'static str {
        "random"
    }

    fn select(&self, upstreams: &[Arc<Upstream>], _request: &Request) -> Option<Arc<Upstream>> {
        // Reservoir sampling over the available upstreams, like Caddy's `selectRandomHost`.
        let mut selected: Option<Arc<Upstream>> = None;
        let mut count = 0_u64;
        for upstream in upstreams.iter().filter(|upstream| upstream.is_healthy()) {
            count += 1;
            if self.next_u64() % count == 0 {
                selected = Some(Arc::clone(upstream));
            }
        }
        selected
    }
}

/// `weighted_round_robin`: weighted rotation over healthy upstreams (Caddy's policy).
pub struct WeightedRoundRobin {
    weights: Vec<u64>,
    total_weight: u64,
    index: AtomicU64,
}

impl WeightedRoundRobin {
    /// Build a weighted round-robin balancer; weights are positional and zeros exclude upstreams.
    pub fn new(weights: Vec<u64>) -> Result<Self, String> {
        let total_weight: u64 = weights.iter().sum();
        if total_weight == 0 {
            return Err(
                "weighted_round_robin requires at least one upstream with a positive weight"
                    .to_string(),
            );
        }
        Ok(Self {
            weights,
            total_weight,
            index: AtomicU64::new(0),
        })
    }
}

impl Balancer for WeightedRoundRobin {
    fn name(&self) -> &'static str {
        "weighted_round_robin"
    }

    fn select(&self, upstreams: &[Arc<Upstream>], _request: &Request) -> Option<Arc<Upstream>> {
        if upstreams.is_empty() {
            return None;
        }
        // Caddy returns the first pool element when fewer than two weights are configured.
        if self.weights.len() < 2 {
            return upstreams
                .iter()
                .find(|upstream| upstream.is_healthy())
                .cloned();
        }
        let positive: Vec<u64> = self
            .weights
            .iter()
            .copied()
            .filter(|weight| *weight > 0)
            .collect();
        let current = (self.index.fetch_add(1, Ordering::AcqRel) % self.total_weight) as i64;
        let mut cumulative = 0_i64;
        let mut bucket = 0_usize;
        for (index, weight) in positive.iter().enumerate() {
            cumulative += *weight as i64;
            if current < cumulative {
                bucket = index;
                break;
            }
        }
        // Follow Caddy's selection over the available, positively-weighted upstreams.
        let available: Vec<Arc<Upstream>> = upstreams
            .iter()
            .enumerate()
            .filter(|(index, upstream)| {
                upstream.is_healthy() && self.weights.get(*index).copied().unwrap_or(0) > 0
            })
            .map(|(_, upstream)| Arc::clone(upstream))
            .collect();
        if available.is_empty() {
            return None;
        }
        Some(Arc::clone(&available[bucket % available.len()]))
    }
}

/// A hash-based selection policy: hashes a per-request key with each upstream's dial address
/// (Caddy's Highest Random Weight / rendezvous hashing) so the selection is stable while the pool
/// changes.
pub struct HashSelection {
    name: &'static str,
    key: HashKey,
    fallback: Box<dyn Balancer>,
}

/// Where a hash selection policy reads its key from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HashKey {
    /// Client IP as seen on the connection (`ip_hash`).
    PeerIp,
    /// Effective client IP from the HTTP app's trusted-proxy handling (`client_ip_hash`).
    ClientIp,
    /// Full request URI including the query (`uri_hash`).
    Uri,
    /// A request header value; `Host` is read from the request host (`header`).
    Header(String),
    /// A query-string parameter; all values for the key are joined with `,` (`query`).
    Query(String),
}

impl HashSelection {
    fn new(name: &'static str, key: HashKey, fallback: Box<dyn Balancer>) -> Self {
        Self {
            name,
            key,
            fallback,
        }
    }

    fn hash_key(&self, request: &Request) -> Option<String> {
        match &self.key {
            HashKey::PeerIp => peer_ip(request).map(|ip| ip.to_string()),
            HashKey::ClientIp => effective_client_ip(request).map(|ip| ip.to_string()),
            HashKey::Uri => Some(
                request
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string()),
            ),
            HashKey::Header(field) => {
                if field.eq_ignore_ascii_case("host") {
                    request.host().map(str::to_string)
                } else {
                    request
                        .headers
                        .get(field.as_str())
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string)
                }
            }
            HashKey::Query(key) => query_values(request.uri.query().unwrap_or_default(), key)
                .filter(|value| !value.is_empty()),
        }
    }
}

impl Balancer for HashSelection {
    fn name(&self) -> &'static str {
        self.name
    }

    fn select(&self, upstreams: &[Arc<Upstream>], request: &Request) -> Option<Arc<Upstream>> {
        match self.hash_key(request) {
            Some(key) => rendezvous_hash(upstreams, &key),
            None => self.fallback.select(upstreams, request),
        }
    }
}

/// Select the healthy upstream with the highest `xxh64(upstream.dial + key)` hash.
fn rendezvous_hash(upstreams: &[Arc<Upstream>], key: &str) -> Option<Arc<Upstream>> {
    let mut best: Option<(u64, Arc<Upstream>)> = None;
    for upstream in upstreams.iter().filter(|upstream| upstream.is_healthy()) {
        let mut input = Vec::with_capacity(upstream.dial.len() + key.len());
        input.extend_from_slice(upstream.dial.as_bytes());
        input.extend_from_slice(key.as_bytes());
        let hash = xxh64(&input);
        if best.as_ref().is_none_or(|(current, _)| hash > *current) {
            best = Some((hash, Arc::clone(upstream)));
        }
    }
    best.map(|(_, upstream)| upstream)
}

/// The peer IP of the connection (Caddy's `ip_hash` input: `req.RemoteAddr`).
fn peer_ip(request: &Request) -> Option<IpAddr> {
    let remote = request.remote_addr?;
    let mut ip = remote.ip();
    if let IpAddr::V6(v6) = ip {
        // Strip an IPv6 zone/scope id the way Caddy does before hashing.
        if let Some((address, _)) = v6.to_string().split_once('%') {
            if let Ok(parsed) = address.parse() {
                ip = parsed;
            }
        }
    }
    Some(ip)
}

/// The effective client IP from the HTTP app's trusted-proxy handling (`client_ip` var), falling
/// back to the connection peer when the server has not set the var (see
/// [`crate::trusted_proxies`]).
fn effective_client_ip(request: &Request) -> Option<IpAddr> {
    request
        .vars
        .get("client_ip")
        .and_then(|value| parse_ip_with_optional_port(value))
        .or_else(|| peer_ip(request))
}

fn parse_ip_with_optional_port(value: &str) -> Option<IpAddr> {
    let value = value.trim();
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

/// Collect all query values for `key` and join them with `,` like Caddy's `query` policy.
fn query_values(query: &str, key: &str) -> Option<String> {
    let mut values = BTreeMap::<usize, Vec<String>>::new();
    let mut order = 0_usize;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(name) == key {
            values.entry(order).or_default().push(percent_decode(value));
        }
        order += 1;
    }
    let joined = values
        .into_values()
        .flatten()
        .collect::<Vec<String>>()
        .join(",");
    (!joined.is_empty()).then_some(joined)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                decoded.push(byte);
                index += 3;
                continue;
            }
        } else if bytes[index] == b'+' {
            decoded.push(b' ');
            index += 1;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Parse the `selection_policy` object of `load_balancing` (Caddy's selector modules).
///
/// Supported policies: `random`, `first`, `round_robin`, `least_conn`, `weighted_round_robin`,
/// `ip_hash`, `client_ip_hash`, `uri_hash`, `header`, and `query`. `cookie` is rejected loudly
/// (it needs to write a `Set-Cookie` response header, which is tracked as a follow-up).
pub fn from_selection_policy(
    selection_policy: Option<&serde_json::Value>,
    path: &str,
) -> Result<Box<dyn Balancer>, BalancerError> {
    from_selection_policy_inner(selection_policy, path, 0)
}

fn from_selection_policy_inner(
    selection_policy: Option<&serde_json::Value>,
    path: &str,
    depth: usize,
) -> Result<Box<dyn Balancer>, BalancerError> {
    if depth > 8 {
        return Err(BalancerError::Invalid(format!(
            "{path}: selection policy fallback nesting is too deep"
        )));
    }
    let Some(selection_policy) = selection_policy.filter(|value| !value.is_null()) else {
        // caddy-rs has historically defaulted to round_robin; Caddy's default is random
        // (documented divergence). Keep the deterministic historical default here.
        return Ok(Box::new(RoundRobin::new()));
    };
    let object = selection_policy.as_object().ok_or_else(|| {
        BalancerError::Invalid(format!("{path}: `selection_policy` must be an object"))
    })?;
    let policy = object
        .get("policy")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BalancerError::Invalid(format!("{path}.selection_policy: missing `policy`"))
        })?;
    let random_fallback = || -> Box<dyn Balancer> { Box::new(Random::new()) };
    let parse_fallback = |field: &str| -> Result<Box<dyn Balancer>, BalancerError> {
        match object.get(field) {
            None | Some(serde_json::Value::Null) => Ok(random_fallback()),
            Some(fallback) => {
                from_selection_policy_inner(Some(fallback), &format!("{path}.{field}"), depth + 1)
            }
        }
    };
    match policy {
        "round_robin" => Ok(Box::new(RoundRobin::new())),
        "first" => Ok(Box::new(First)),
        "least_conn" => Ok(Box::new(LeastConnections)),
        "random" => Ok(Box::new(Random::new())),
        "weighted_round_robin" => {
            let weights = object
                .get("weights")
                .map(|weights| {
                    weights
                        .as_array()
                        .ok_or_else(|| {
                            BalancerError::Invalid(format!(
                                "{path}: `weights` must be an array of numbers"
                            ))
                        })?
                        .iter()
                        .map(|weight| {
                            weight.as_u64().ok_or_else(|| {
                                BalancerError::Invalid(format!(
                                    "{path}: `weights` entries must be non-negative integers"
                                ))
                            })
                        })
                        .collect::<Result<Vec<u64>, BalancerError>>()
                })
                .transpose()?
                .unwrap_or_default();
            WeightedRoundRobin::new(weights)
                .map(|balancer| Box::new(balancer) as Box<dyn Balancer>)
                .map_err(|message| BalancerError::Invalid(format!("{path}: {message}")))
        }
        "ip_hash" => Ok(Box::new(HashSelection::new(
            "ip_hash",
            HashKey::PeerIp,
            random_fallback(),
        ))),
        "client_ip_hash" => Ok(Box::new(HashSelection::new(
            "client_ip_hash",
            HashKey::ClientIp,
            random_fallback(),
        ))),
        "uri_hash" => Ok(Box::new(HashSelection::new(
            "uri_hash",
            HashKey::Uri,
            random_fallback(),
        ))),
        "header" => {
            let field = object
                .get("field")
                .and_then(serde_json::Value::as_str)
                .filter(|field| !field.is_empty())
                .ok_or_else(|| {
                    BalancerError::Invalid(format!(
                        "{path}: `header` selection policy requires a non-empty `field`"
                    ))
                })?;
            Ok(Box::new(HashSelection::new(
                "header",
                HashKey::Header(field.to_string()),
                parse_fallback("fallback")?,
            )))
        }
        "query" => {
            let key = object
                .get("key")
                .and_then(serde_json::Value::as_str)
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    BalancerError::Invalid(format!(
                        "{path}: `query` selection policy requires a non-empty `key`"
                    ))
                })?;
            Ok(Box::new(HashSelection::new(
                "query",
                HashKey::Query(key.to_string()),
                parse_fallback("fallback")?,
            )))
        }
        "cookie" => Err(BalancerError::NotImplemented {
            feature: "the cookie load-balancing selection policy",
            tracking_id: "T-PROXY-013-COOKIE",
        }),
        "random_choose" => Err(BalancerError::NotImplemented {
            feature: "the random_choose load-balancing selection policy",
            tracking_id: "T-PROXY-013-RANDOM-CHOOSE",
        }),
        other => Err(BalancerError::Invalid(format!(
            "{path}: load-balancing policy `{other}` is not implemented by this build"
        ))),
    }
}

/// 64-bit xxHash (seed 0), the hash Caddy uses for selection policies.
fn xxh64(bytes: &[u8]) -> u64 {
    const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

    fn round(accumulator: u64, input: u64) -> u64 {
        accumulator
            .wrapping_add(input.wrapping_mul(PRIME2))
            .rotate_left(31)
            .wrapping_mul(PRIME1)
    }
    fn merge_round(accumulator: u64, value: u64) -> u64 {
        (accumulator ^ round(0, value))
            .wrapping_mul(PRIME1)
            .wrapping_add(PRIME4)
    }

    let length = bytes.len() as u64;
    let mut offset = 0usize;
    let mut hash = if bytes.len() >= 32 {
        let mut v1 = PRIME1.wrapping_add(PRIME2);
        let mut v2 = PRIME2;
        let mut v3 = 0u64;
        let mut v4 = 0u64.wrapping_sub(PRIME1);
        while offset + 32 <= bytes.len() {
            let read = |at: usize| {
                let mut value = [0u8; 8];
                value.copy_from_slice(&bytes[at..at + 8]);
                u64::from_le_bytes(value)
            };
            v1 = round(v1, read(offset));
            v2 = round(v2, read(offset + 8));
            v3 = round(v3, read(offset + 16));
            v4 = round(v4, read(offset + 24));
            offset += 32;
        }
        let mut hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        hash = merge_round(hash, v1);
        hash = merge_round(hash, v2);
        hash = merge_round(hash, v3);
        hash = merge_round(hash, v4);
        hash
    } else {
        PRIME5
    };

    hash = hash.wrapping_add(length);
    while offset + 8 <= bytes.len() {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[offset..offset + 8]);
        let k1 = round(0, u64::from_le_bytes(value));
        hash ^= k1;
        hash = hash
            .rotate_left(27)
            .wrapping_mul(PRIME1)
            .wrapping_add(PRIME4);
        offset += 8;
    }
    if offset + 4 <= bytes.len() {
        let mut value = [0u8; 4];
        value.copy_from_slice(&bytes[offset..offset + 4]);
        hash ^= u64::from(u32::from_le_bytes(value)).wrapping_mul(PRIME1);
        hash = hash
            .rotate_left(23)
            .wrapping_mul(PRIME2)
            .wrapping_add(PRIME3);
        offset += 4;
    }
    while offset < bytes.len() {
        hash ^= u64::from(bytes[offset]).wrapping_mul(PRIME5);
        hash = hash.rotate_left(11).wrapping_mul(PRIME1);
        offset += 1;
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME3);
    hash ^= hash >> 32;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn pool(count: usize) -> Vec<Arc<Upstream>> {
        (0..count)
            .map(|index| Arc::new(Upstream::new(format!("localhost:{}", 9000 + index), false)))
            .collect()
    }

    fn get(path: &str) -> Request {
        Request::new(Method::GET, path.parse().unwrap())
    }

    #[test]
    fn first_prefers_first_healthy() {
        let pool = pool(3);
        pool[0].set_healthy(false);
        let selected = First.select(&pool, &get("/")).unwrap();
        assert_eq!(selected.dial, "localhost:9001");
    }

    #[test]
    fn round_robin_rotates() {
        let pool = pool(3);
        let request = get("/");
        let selected: Vec<String> = (0..3)
            .map(|_| RoundRobin::new().select(&pool, &request))
            .map(|upstream| upstream.unwrap().dial.clone())
            .collect();
        // A fresh balancer starts at index 0.
        assert_eq!(selected, ["localhost:9000"; 3]);
        let balancer = RoundRobin::new();
        let selected: Vec<String> = (0..4)
            .map(|_| balancer.select(&pool, &request).unwrap().dial.clone())
            .collect();
        assert_eq!(
            selected,
            [
                "localhost:9000",
                "localhost:9001",
                "localhost:9002",
                "localhost:9000"
            ]
        );
    }

    #[test]
    fn least_conn_picks_least_busy() {
        let pool = pool(3);
        let _first = pool[0].connection_started();
        let _second = pool[1].connection_started();
        let selected = LeastConnections.select(&pool, &get("/")).unwrap();
        assert_eq!(selected.dial, "localhost:9002");
    }

    #[test]
    fn xxh64_matches_reference_vectors() {
        // Vectors from xxHash's reference implementation (the same ones the admin ETag tests use).
        assert_eq!(xxh64(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"abc"), 0x44BC_2CF5_AD77_0999);
        assert_eq!(xxh64(b"hello"), 0x26C7_827D_889F_6DA3);
        assert_eq!(xxh64(b"message digest"), 0x066E_D728_FCEE_B3BE);
    }

    #[test]
    fn hash_policies_are_stable_per_key_and_respect_health() {
        let pool = pool(3);
        for key in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
            let first = rendezvous_hash(&pool, key).unwrap();
            for _ in 0..10 {
                assert_eq!(
                    rendezvous_hash(&pool, key).unwrap().dial,
                    first.dial,
                    "hash selection must be stable for `{key}`"
                );
            }
        }
        // Multiple keys spread across the pool.
        let mut selected = std::collections::BTreeSet::new();
        for index in 0..100 {
            selected.insert(
                rendezvous_hash(&pool, &format!("key-{index}"))
                    .unwrap()
                    .dial
                    .clone(),
            );
        }
        assert!(selected.len() > 1, "hash selection must spread keys");
        // Health is respected: a pool of one healthy upstream always picks it.
        pool[0].set_healthy(false);
        pool[1].set_healthy(false);
        assert_eq!(
            rendezvous_hash(&pool, "any-key").unwrap().dial,
            "localhost:9002"
        );
    }

    #[test]
    fn random_policy_is_deterministic_with_seed_and_respects_health() {
        let pool = pool(4);
        pool[3].set_healthy(false);
        let request = get("/");
        let balancer = Random::with_seed(42);
        let mut selected = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let upstream = balancer.select(&pool, &request).unwrap();
            assert_ne!(upstream.dial, "localhost:9003", "unhealthy upstream chosen");
            selected.insert(upstream.dial.clone());
        }
        assert!(
            selected.len() >= 2,
            "random selection must use multiple healthy upstreams"
        );
        // Same seed produces the same sequence.
        let first: Vec<String> = (0..5)
            .map(|_| {
                Random::with_seed(7)
                    .select(&pool, &request)
                    .unwrap()
                    .dial
                    .clone()
            })
            .collect();
        let second: Vec<String> = (0..5)
            .map(|_| {
                Random::with_seed(7)
                    .select(&pool, &request)
                    .unwrap()
                    .dial
                    .clone()
            })
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn weighted_round_robin_honours_weights() {
        let pool = pool(2);
        let balancer = WeightedRoundRobin::new(vec![3, 1]).unwrap();
        let request = get("/");
        let selected: Vec<String> = (0..8)
            .map(|_| balancer.select(&pool, &request).unwrap().dial.clone())
            .collect();
        let first = selected
            .iter()
            .filter(|dial| *dial == "localhost:9000")
            .count();
        let second = selected
            .iter()
            .filter(|dial| *dial == "localhost:9001")
            .count();
        assert_eq!(first, 6, "3:1 weights over 8 selections: {selected:?}");
        assert_eq!(second, 2, "3:1 weights over 8 selections: {selected:?}");
        assert!(WeightedRoundRobin::new(vec![0, 0]).is_err());
    }

    #[test]
    fn header_host_hash_uses_request_host() {
        let pool = pool(3);
        let mut request = get("/");
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let balancer = from_selection_policy(
            Some(&serde_json::json!({"policy": "header", "field": "Host"})),
            "handler",
        )
        .unwrap();
        let first = balancer.select(&pool, &request).unwrap().dial.clone();
        for _ in 0..5 {
            assert_eq!(balancer.select(&pool, &request).unwrap().dial, first);
        }
        request
            .headers
            .insert(http::header::HOST, "other.example".parse().unwrap());
        // A different key may map to a different upstream (it is deterministic either way).
        let _ = balancer.select(&pool, &request).unwrap();
    }

    #[test]
    fn header_hash_falls_back_when_header_missing() {
        let pool = pool(2);
        let balancer = from_selection_policy(
            Some(&serde_json::json!({"policy": "header", "field": "X-Session"})),
            "handler",
        )
        .unwrap();
        let request = get("/");
        assert!(balancer.select(&pool, &request).is_some());
        let mut request = get("/");
        request.headers.insert("x-session", "abc".parse().unwrap());
        assert!(balancer.select(&pool, &request).is_some());
    }

    #[test]
    fn query_hash_joins_values_and_falls_back() {
        let pool = pool(2);
        let balancer = from_selection_policy(
            Some(&serde_json::json!({"policy": "query", "key": "user"})),
            "handler",
        )
        .unwrap();
        let request = get("/?user=alice&user=bob");
        let selected = balancer.select(&pool, &request).unwrap();
        assert!(pool.iter().any(|upstream| upstream.dial == selected.dial));
        // Missing key uses the random fallback.
        let request = get("/?other=1");
        assert!(balancer.select(&pool, &request).is_some());
    }

    #[test]
    fn client_ip_hash_uses_effective_client_ip_var() {
        let pool = pool(3);
        let mut request = get("/");
        request.remote_addr = Some("192.0.2.1:5000".parse().unwrap());
        request
            .vars
            .insert("client_ip".to_string(), "203.0.113.7".to_string());
        let balancer = from_selection_policy(
            Some(&serde_json::json!({"policy": "client_ip_hash"})),
            "handler",
        )
        .unwrap();
        let by_var = balancer.select(&pool, &request).unwrap().dial.clone();
        // The peer IP would hash to a different key; verify the var is what is used.
        request.remote_addr = Some("192.0.2.2:5000".parse().unwrap());
        assert_eq!(balancer.select(&pool, &request).unwrap().dial, by_var);
        // Without the var the peer IP is used.
        request.vars.clear();
        let _ = balancer.select(&pool, &request);
    }

    #[test]
    fn parses_selection_policy_modules() {
        assert_eq!(
            from_selection_policy(None, "handler").unwrap().name(),
            "round_robin"
        );
        for (policy, expected) in [
            (serde_json::json!({"policy": "random"}), "random"),
            (serde_json::json!({"policy": "first"}), "first"),
            (serde_json::json!({"policy": "round_robin"}), "round_robin"),
            (serde_json::json!({"policy": "least_conn"}), "least_conn"),
            (
                serde_json::json!({"policy": "weighted_round_robin", "weights": [1, 2]}),
                "weighted_round_robin",
            ),
            (serde_json::json!({"policy": "ip_hash"}), "ip_hash"),
            (
                serde_json::json!({"policy": "client_ip_hash"}),
                "client_ip_hash",
            ),
            (serde_json::json!({"policy": "uri_hash"}), "uri_hash"),
            (
                serde_json::json!({"policy": "header", "field": "X-Session"}),
                "header",
            ),
            (
                serde_json::json!({"policy": "query", "key": "user"}),
                "query",
            ),
        ] {
            assert_eq!(
                from_selection_policy(Some(&policy), "handler")
                    .unwrap()
                    .name(),
                expected,
                "{policy}"
            );
        }
        let error =
            from_selection_policy(Some(&serde_json::json!({"policy": "header"})), "handler")
                .err()
                .expect("header policy without field must fail");
        assert!(error.to_string().contains("field"), "{error}");
        let error = from_selection_policy(
            Some(&serde_json::json!({"policy": "cookie", "name": "lb"})),
            "handler",
        )
        .err()
        .expect("cookie policy must be rejected loudly");
        assert!(
            matches!(error, BalancerError::NotImplemented { tracking_id, .. } if tracking_id == "T-PROXY-013-COOKIE")
        );
        let error = from_selection_policy(Some(&serde_json::json!({"policy": "magic"})), "handler")
            .err()
            .expect("unknown policy must fail");
        assert!(error.to_string().contains("magic"), "{error}");
    }

    #[test]
    fn fallback_policy_is_parsed_recursively() {
        let policy = serde_json::json!({
            "policy": "header",
            "field": "X-Session",
            "fallback": {"policy": "first"}
        });
        let balancer = from_selection_policy(Some(&policy), "handler").unwrap();
        assert_eq!(balancer.name(), "header");
        let pool = pool(2);
        // No header on the request: the `first` fallback picks the first upstream.
        assert_eq!(
            balancer.select(&pool, &get("/")).unwrap().dial,
            "localhost:9000"
        );
    }
}
