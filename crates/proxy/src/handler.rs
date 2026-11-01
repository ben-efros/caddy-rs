//! The `reverse_proxy` handler.
//!
//! Header handling follows Caddy's `prepareRequest` / `addForwardedHeaders` semantics:
//!
//! * The client's `Host` header is forwarded unchanged (Caddy only rewrites it through `header_up`
//!   operations or a transport-level host).
//! * Hop-by-hop headers are stripped (including headers named by the `Connection` header).
//! * `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set from the connection.
//!   Prior values are only trusted when the peer is in `trusted_proxies`.
//! * `Via` is appended to the upstream response, matching Caddy.
//!
//! Upstreams may be `host:port` TCP dials or Unix sockets (`unix//path`); the shared
//! [`crate::client::HttpClient`] selects the transport from the outbound URI.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use serde_json::Value;

use caddy_rs_http::{
    CustomHandlerFactory, Error as HttpError, Handler, Outcome, Request, Response,
    Result as HttpResult,
};

use crate::balancer::{self, Balancer};
use crate::client::{build_client_with_tls, HttpClient};
use crate::health::{HealthCheck, HealthCheckScheduler};
use crate::passive::PassiveHealth;
use crate::retry::RetryMatch;
use crate::tls::UpstreamTls;
use crate::upstream::Upstream;

/// Headers Caddy strips in both directions (see `hopHeaders` in upstream `reverseproxy.go`).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "alt-svc",
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

#[derive(Debug, thiserror::Error)]
enum ProxyError {
    #[error("cannot build upstream request: {0}")]
    Request(String),
    #[error("transport error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("cannot read upstream response body: {0}")]
    Body(String),
}

impl ProxyError {
    /// Whether this failure happened before any bytes of the request reached the upstream.
    ///
    /// A dial failure is always safe to retry, even for non-idempotent methods (Caddy's
    /// `DialError` rule); other transport errors are only retried when `retry_match` opts in.
    fn is_dial_error(&self) -> bool {
        match self {
            ProxyError::Client(error) => error.is_connect(),
            _ => false,
        }
    }
}

/// One proxied upstream response, before conversion into the HTTP engine's [`Response`].
struct ForwardedResponse {
    status: StatusCode,
    /// Time until the upstream sent its response headers (Caddy's roundtrip duration).
    latency: Duration,
    headers: HeaderMap,
    body: Bytes,
}

/// A CIDR or single-address trusted proxy range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    address: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(text: &str) -> Result<Self, String> {
        let (address_text, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address_text
            .parse()
            .map_err(|_| format!("`{text}` is not an IP address or CIDR range"))?;
        let maximum = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_text {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("`{text}` has an invalid prefix length"))?,
            None => maximum,
        };
        if prefix > maximum {
            return Err(format!(
                "`{text}` has a prefix length greater than {maximum}"
            ));
        }
        Ok(Self { address, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(network) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(network) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

/// Reverse proxy handler configuration and runtime.
pub struct ReverseProxyHandler {
    client: HttpClient,
    upstreams: Vec<Arc<Upstream>>,
    balancer: Box<dyn Balancer>,
    request_headers_set: HeaderMap,
    response_headers_set: HeaderMap,
    response_headers_add: HeaderMap,
    response_headers_delete: Vec<HeaderName>,
    retries: u32,
    try_duration: Duration,
    try_interval: Duration,
    health_check: Option<Arc<HealthCheck>>,
    passive: Option<PassiveHealth>,
    retry_match: RetryMatch,
    trusted_proxies: Vec<IpNet>,
}

impl ReverseProxyHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "reverse_proxy handler must be an object"))?;

        // `transport.tls` enables TLS for every upstream of the handler (Caddy's transport is
        // per-handler, not per-upstream). The client configuration is built here so trust-store
        // failures surface as located config errors instead of per-request transport errors.
        let tls = parse_transport(object.get("transport"), path)?;

        let upstreams_value = object
            .get("upstreams")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(path, "reverse_proxy requires an `upstreams` array"))?;
        let mut upstreams = Vec::new();
        for (index, upstream) in upstreams_value.iter().enumerate() {
            let upstream_path = format!("{path}.upstreams[{index}]");
            let dial = upstream
                .get("dial")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(&upstream_path, "upstream requires a `dial` string"))?;
            let parsed = Upstream::parse_dial(dial, tls.is_some())
                .map_err(|message| invalid(&upstream_path, message))?;
            upstreams.push(Arc::new(parsed));
        }
        if let Some(tls) = &tls {
            validate_unix_tls(&upstreams, tls, path)?;
        }

        let load_balancing = object.get("load_balancing");
        let policy = load_balancing
            .and_then(|lb| lb.get("selection_policy"))
            .and_then(|policy| policy.get("policy"))
            .and_then(Value::as_str);
        let balancer = balancer::from_policy(policy).map_err(|message| invalid(path, message))?;
        let retries = load_balancing
            .and_then(|lb| lb.get("retries"))
            .and_then(Value::as_u64)
            .map(|retries| u32::try_from(retries).unwrap_or(u32::MAX))
            .unwrap_or(0);
        let try_duration = load_balancing
            .and_then(|lb| lb.get("try_duration"))
            .and_then(Value::as_u64)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let try_interval = load_balancing
            .and_then(|lb| lb.get("try_interval"))
            .and_then(Value::as_u64)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let retry_match = RetryMatch::from_json(
            load_balancing.and_then(|lb| lb.get("retry_match")),
            &format!("{path}.load_balancing.retry_match"),
        )?;

        let (
            request_headers_set,
            response_headers_set,
            response_headers_add,
            response_headers_delete,
        ) = parse_headers(object.get("headers"), path)?;

        let trusted_proxies = parse_trusted_proxies(object.get("trusted_proxies"), path)?;

        let (health_check, passive) = parse_health_checks(object.get("health_checks"), path)?;

        Ok(Self {
            client: build_client_with_tls(tls),
            upstreams,
            balancer,
            request_headers_set,
            response_headers_set,
            response_headers_add,
            response_headers_delete,
            retries,
            try_duration,
            try_interval,
            health_check,
            passive,
            retry_match,
            trusted_proxies,
        })
    }

    /// Active health-check configuration, if configured.
    pub fn health_check(&self) -> Option<Arc<HealthCheck>> {
        self.health_check.clone()
    }

    /// Upstreams, for health-check scheduling.
    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// The outbound client (TLS-aware), exposed for crate-level health-check tests.
    #[cfg(test)]
    pub(crate) fn client(&self) -> &HttpClient {
        &self.client
    }

    /// Passive health-check state, when `health_checks.passive` is configured.
    pub fn passive_health(&self) -> Option<&PassiveHealth> {
        self.passive.as_ref()
    }

    /// Spawn the active-health-check scheduler for this handler's upstreams, when configured.
    ///
    /// The caller owns the returned handle and calls [`HealthCheckScheduler::shutdown`] when the
    /// handler generation is torn down (for example on config reload). This keeps the proxy crate
    /// free of runtime-lifetime concerns while making the scheduler drivable by the server crate.
    pub fn spawn_health_checks(&self) -> Option<HealthCheckScheduler> {
        self.health_check.as_ref().map(|check| {
            HealthCheckScheduler::spawn(
                Arc::clone(check),
                self.upstreams.clone(),
                self.client.clone(),
            )
        })
    }

    async fn forward(
        &self,
        upstream: &Upstream,
        request: &Request,
    ) -> Result<ForwardedResponse, ProxyError> {
        let path_and_query = request
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let url = upstream.url(path_and_query);
        let headers = self.outbound_headers(request, upstream)?;

        let mut outbound = hyper::Request::builder()
            .method(request.method.clone())
            .uri(url)
            .body(Full::new(request.body.clone()))
            .map_err(|error| ProxyError::Request(error.to_string()))?;
        *outbound.headers_mut() = headers;

        let started = std::time::Instant::now();
        let response = self.client.request(outbound).await?;
        let latency = started.elapsed();
        let status = response.status();
        let version = response.version();
        let response_headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ProxyError::Body(error.to_string()))?
            .to_bytes();
        Ok(ForwardedResponse {
            status,
            latency,
            headers: self.response_headers(&response_headers, version),
            body,
        })
    }

    /// Build the headers sent to the upstream, following Caddy's `prepareRequest`.
    fn outbound_headers(
        &self,
        request: &Request,
        upstream: &Upstream,
    ) -> Result<HeaderMap, ProxyError> {
        let mut headers = strip_hop_by_hop(&request.headers);

        // Go's reverse proxy keeps `TE: trailers` so backends know trailers are supported.
        if header_has_token(&request.headers, http::header::TE, "trailers") {
            headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
        }

        // Caddy forwards the client's Host header unchanged; the URI authority is only the dial
        // target. A request without a Host falls back to the upstream address (or `localhost`
        // for Unix sockets), matching what Go's transport does.
        let host = request.host().unwrap_or_else(|| upstream.fallback_host());
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(host).map_err(|error| ProxyError::Request(error.to_string()))?,
        );

        self.add_forwarded_headers(&mut headers, request, upstream)?;

        // `header_up` operations are applied last and win over the implicit headers.
        for (name, value) in &self.request_headers_set {
            headers.insert(name.clone(), value.clone());
        }
        Ok(headers)
    }

    /// Set `X-Forwarded-*` headers from the connection, trusting prior values only for peers in
    /// `trusted_proxies` (Caddy's `addForwardedHeaders`).
    fn add_forwarded_headers(
        &self,
        headers: &mut HeaderMap,
        request: &Request,
        upstream: &Upstream,
    ) -> Result<(), ProxyError> {
        let Some(remote) = request.remote_addr.as_ref() else {
            // Caddy treats a Unix-socket peer as remote address "@": it cannot be a trusted
            // proxy, so forwarded headers sent by the client are stripped.
            headers.remove("x-forwarded-for");
            headers.remove("x-forwarded-proto");
            headers.remove("x-forwarded-host");
            return Ok(());
        };
        let client_ip = remote.ip();
        let trusted = self
            .trusted_proxies
            .iter()
            .any(|network| network.contains(client_ip));

        let forwarded_for = joined_header_value(headers, "x-forwarded-for");
        if trusted
            && forwarded_for
                .as_deref()
                .is_some_and(|prior| !prior.is_empty())
        {
            let mut prior = forwarded_for.unwrap_or_default();
            prior.push_str(", ");
            prior.push_str(&client_ip.to_string());
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&prior)
                    .map_err(|error| ProxyError::Request(error.to_string()))?,
            );
        } else {
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&client_ip.to_string())
                    .map_err(|error| ProxyError::Request(error.to_string()))?,
            );
        }

        // X-Forwarded-Proto: the trusted proxy's value wins, else the actual connection scheme.
        let mut proto = if request.tls { "https" } else { "http" }.to_string();
        if trusted {
            if let Some(prior) = last_header_value(headers, "x-forwarded-proto") {
                if !prior.is_empty() {
                    proto = prior;
                }
            }
        }
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_str(&proto)
                .map_err(|error| ProxyError::Request(error.to_string()))?,
        );

        // X-Forwarded-Host: the trusted proxy's value wins, else the original Host.
        let mut host = request
            .host()
            .unwrap_or_else(|| upstream.fallback_host())
            .to_string();
        if trusted {
            if let Some(prior) = last_header_value(headers, "x-forwarded-host") {
                if !prior.is_empty() {
                    host = prior;
                }
            }
        }
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_str(&host).map_err(|error| ProxyError::Request(error.to_string()))?,
        );
        Ok(())
    }

    /// Strip hop-by-hop headers from an upstream response and add the `Via` header Caddy adds.
    fn response_headers(&self, upstream_headers: &HeaderMap, version: Version) -> HeaderMap {
        let mut headers = strip_hop_by_hop(upstream_headers);
        headers.append(
            http::header::VIA,
            HeaderValue::from_static(via_value(version)),
        );
        headers
    }

    fn apply_response_headers(&self, response: &mut Response) {
        for (name, value) in &self.response_headers_set {
            response.headers.insert(name.clone(), value.clone());
        }
        for (name, value) in &self.response_headers_add {
            response.headers.append(name.clone(), value.clone());
        }
        for name in &self.response_headers_delete {
            response.headers.remove(name);
        }
    }

    /// Whether another attempt is allowed after `attempts` retries have already been performed.
    ///
    /// Mirrors Caddy's `tryAgain`: retries stop when neither `lb_retries` nor `lb_try_duration`
    /// is configured, when the retry budget is spent, or when the try duration has elapsed.
    fn retry_allowed(&self, attempts: u32, deadline: Option<tokio::time::Instant>) -> bool {
        if self.retries == 0 && self.try_duration.is_zero() {
            return false;
        }
        if self.retries > 0 && attempts >= self.retries {
            return false;
        }
        if let Some(deadline) = deadline {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
        }
        true
    }

    async fn wait_before_retry(&self) {
        if !self.try_interval.is_zero() {
            tokio::time::sleep(self.try_interval).await;
        }
    }
}

#[async_trait]
impl Handler for ReverseProxyHandler {
    fn name(&self) -> &'static str {
        "reverse_proxy"
    }

    async fn handle(&self, request: Request) -> HttpResult<Outcome> {
        let deadline = if self.try_duration.is_zero() {
            None
        } else {
            Some(tokio::time::Instant::now() + self.try_duration)
        };
        // Number of retries already performed (Caddy's `retries` in `tryAgain`).
        let mut attempts: u32 = 0;
        loop {
            // Passive health checks remove temporarily unhealthy (or saturated) upstreams from
            // selection until their failure window expires (Caddy's `Upstream.Available()`).
            let now = std::time::Instant::now();
            let candidates: Vec<Arc<Upstream>> = match &self.passive {
                Some(passive) => self
                    .upstreams
                    .iter()
                    .filter(|upstream| {
                        passive.is_available(&upstream.dial, now, upstream.active_connections())
                    })
                    .cloned()
                    .collect(),
                None => self.upstreams.clone(),
            };
            let Some(upstream) = self.balancer.select(&candidates) else {
                // No upstream is available. Caddy retries this state (an upstream may recover)
                // and surfaces 503 when the retry budget is spent.
                if !self.retry_allowed(attempts, deadline) {
                    return Ok(Outcome::Respond(Response::text(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "503 Service Unavailable",
                    )));
                }
                attempts += 1;
                self.wait_before_retry().await;
                continue;
            };
            let _guard = upstream.connection_started();
            match self.forward(&upstream, &request).await {
                Ok(forwarded) => {
                    // Caddy applies passive response checks before deciding on retry_match, so an
                    // unhealthy_status strike is recorded even when the response is retried.
                    if let Some(passive) = &self.passive {
                        passive.record_response(
                            &upstream.dial,
                            forwarded.status,
                            forwarded.latency,
                            std::time::Instant::now(),
                        );
                    }
                    let mut response = Response {
                        status: forwarded.status,
                        headers: forwarded.headers,
                        body: forwarded.body,
                    };
                    if self.retry_match.matches_response(&request, &response) {
                        if self.retry_allowed(attempts, deadline) {
                            attempts += 1;
                            self.wait_before_retry().await;
                            continue;
                        }
                        // Caddy closes the matched response body and surfaces the upstream status
                        // once the retry budget is spent (rather than a generic 502).
                        return Ok(Outcome::Respond(Response {
                            status: forwarded.status,
                            headers: HeaderMap::new(),
                            body: Bytes::new(),
                        }));
                    }
                    self.apply_response_headers(&mut response);
                    return Ok(Outcome::Respond(response));
                }
                Err(error) => {
                    eprintln!(
                        "caddy-rs: reverse_proxy upstream `{}` failed: {error}",
                        upstream.dial
                    );
                    if let Some(passive) = &self.passive {
                        passive.record_failure(&upstream.dial, std::time::Instant::now());
                    }
                    let retryable =
                        error.is_dial_error() || self.retry_match.matches_transport_error(&request);
                    if !retryable || !self.retry_allowed(attempts, deadline) {
                        return Ok(Outcome::Respond(Response::text(
                            StatusCode::BAD_GATEWAY,
                            "502 Bad Gateway",
                        )));
                    }
                    attempts += 1;
                    self.wait_before_retry().await;
                }
            }
        }
    }
}

/// Build a fresh header map without hop-by-hop headers from `source`.
///
/// Headers named by tokens in `Connection` are dropped as well (RFC 7230 §6.1).
fn strip_hop_by_hop(source: &HeaderMap) -> HeaderMap {
    let mut connection_tokens: Vec<HeaderName> = Vec::new();
    for value in source.get_all(http::header::CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(name) = token.parse::<HeaderName>() {
                connection_tokens.push(name);
            }
        }
    }

    let mut headers = HeaderMap::with_capacity(source.len());
    for (name, value) in source {
        if is_hop_by_hop(name) || connection_tokens.contains(name) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers
}

/// Whether a comma-separated header contains `token`, case-insensitively.
fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// Join all values of a header with `, ` (Caddy's `allHeaderValues`).
fn joined_header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        values.push(value.to_str().unwrap_or_default());
    }
    if values.is_empty() {
        return None;
    }
    Some(values.join(", "))
}

/// Last value of a header (Caddy's `lastHeaderValue`).
fn last_header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// The `Via` entry Caddy appends for a given upstream HTTP version.
fn via_value(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9 Caddy",
        Version::HTTP_10 => "1.0 Caddy",
        Version::HTTP_2 => "2.0 Caddy",
        Version::HTTP_3 => "3.0 Caddy",
        _ => "1.1 Caddy",
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|hop| name.as_str().eq_ignore_ascii_case(hop))
}

fn parse_trusted_proxies(value: Option<&Value>, path: &str) -> HttpResult<Vec<IpNet>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or_else(|| {
        invalid(
            &format!("{path}.trusted_proxies"),
            "`trusted_proxies` must be an array of IP addresses or CIDR ranges",
        )
    })?;
    let mut networks = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let text = entry.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}.trusted_proxies[{index}]"),
                "trusted proxy entries must be strings",
            )
        })?;
        networks
            .push(IpNet::parse(text).map_err(|message| {
                invalid(&format!("{path}.trusted_proxies[{index}]"), message)
            })?);
    }
    Ok(networks)
}

fn parse_headers(
    value: Option<&Value>,
    path: &str,
) -> HttpResult<(HeaderMap, HeaderMap, HeaderMap, Vec<HeaderName>)> {
    let mut request_set = HeaderMap::new();
    let mut response_set = HeaderMap::new();
    let mut response_add = HeaderMap::new();
    let mut response_delete = Vec::new();
    let Some(value) = value else {
        return Ok((request_set, response_set, response_add, response_delete));
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`headers` must be an object"))?;
    if let Some(request) = object.get("request") {
        if let Some(set) = request.get("set") {
            request_set = parse_header_map(set, &format!("{path}.headers.request.set"))?;
        }
    }
    if let Some(response) = object.get("response") {
        if let Some(set) = response.get("set") {
            response_set = parse_header_map(set, &format!("{path}.headers.response.set"))?;
        }
        if let Some(add) = response.get("add") {
            response_add = parse_header_map(add, &format!("{path}.headers.response.add"))?;
        }
        if let Some(delete) = response.get("delete").and_then(Value::as_array) {
            for (index, name) in delete.iter().enumerate() {
                let name = name.as_str().ok_or_else(|| {
                    invalid(
                        &format!("{path}.headers.response.delete[{index}]"),
                        "expected a header name",
                    )
                })?;
                response_delete.push(name.parse().map_err(|error| {
                    invalid(
                        &format!("{path}.headers.response.delete[{index}]"),
                        format!("{error}"),
                    )
                })?);
            }
        }
    }
    Ok((request_set, response_set, response_add, response_delete))
}

fn parse_header_map(value: &Value, path: &str) -> HttpResult<HeaderMap> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    let mut headers = HeaderMap::new();
    for (field, value) in object {
        let name: HeaderName = field
            .parse()
            .map_err(|error| invalid(path, format!("invalid header name `{field}`: {error}")))?;
        let values: Vec<&str> = match value {
            Value::String(value) => vec![value],
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| invalid(path, "header values must be strings"))
                })
                .collect::<HttpResult<_>>()?,
            _ => return Err(invalid(path, "header value must be a string or array")),
        };
        for value in values {
            headers.append(
                name.clone(),
                HeaderValue::from_str(value)
                    .map_err(|error| invalid(path, format!("invalid header value: {error}")))?,
            );
        }
    }
    Ok(headers)
}

/// Parse `transport` (Caddy `http` transport only) and build the TLS client configuration when
/// `transport.tls` is configured.
///
/// TLS is enabled by the mere presence of the `tls` object, even `{}` (Caddy semantics). Options
/// this build cannot honour fail loudly instead of silently changing transport behaviour.
fn parse_transport(value: Option<&Value>, path: &str) -> HttpResult<Option<Arc<UpstreamTls>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let transport_path = format!("{path}.transport");
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&transport_path, "`transport` must be an object"))?;

    if let Some(protocol) = object.get("protocol").and_then(Value::as_str) {
        if protocol != "http" {
            return Err(HttpError::NotImplemented {
                feature: "non-HTTP upstream transports (for example FastCGI)",
                tracking_id: "PROXY-TRANSPORT-PROTOCOL",
            });
        }
    }

    if let Some(versions) = object.get("versions") {
        let versions = versions.as_array().ok_or_else(|| {
            invalid(
                &format!("{transport_path}.versions"),
                "`versions` must be an array of strings",
            )
        })?;
        for version in versions {
            let Some(version) = version.as_str() else {
                return Err(invalid(
                    &format!("{transport_path}.versions"),
                    "`versions` entries must be strings",
                ));
            };
            if !matches!(version, "1" | "1.1") {
                return Err(HttpError::NotImplemented {
                    feature: "HTTP/2 upstream transports (h2c/h2)",
                    tracking_id: "PROXY-H2-UPSTREAM",
                });
            }
        }
    }

    // Real Caddy transport knobs that this build does not implement: reject rather than ignore.
    const UNSUPPORTED_TRANSPORT_OPTIONS: &[(&str, &str, &str)] = &[
        (
            "keep_alive",
            "PROXY-TRANSPORT-KEEPALIVE",
            "HTTP transport keep-alive tuning",
        ),
        (
            "dial_timeout",
            "PROXY-TRANSPORT-DIAL-TIMEOUT",
            "HTTP transport dial timeout",
        ),
        (
            "dial_fallback_delay",
            "PROXY-TRANSPORT-FALLBACK-DELAY",
            "HTTP transport dial fallback delay",
        ),
        (
            "response_header_timeout",
            "PROXY-TRANSPORT-RESPONSE-TIMEOUT",
            "HTTP transport response header timeout",
        ),
        (
            "read_buffer_size",
            "PROXY-TRANSPORT-BUFFERS",
            "HTTP transport read buffer sizing",
        ),
        (
            "write_buffer_size",
            "PROXY-TRANSPORT-BUFFERS",
            "HTTP transport write buffer sizing",
        ),
        (
            "max_response_header_size",
            "PROXY-TRANSPORT-BUFFERS",
            "HTTP transport response header size limits",
        ),
        (
            "local_address",
            "PROXY-TRANSPORT-LOCAL-ADDRESS",
            "HTTP transport local address binding",
        ),
        (
            "resolver",
            "PROXY-TRANSPORT-RESOLVER",
            "HTTP transport custom DNS resolvers",
        ),
        (
            "compression",
            "PROXY-TRANSPORT-COMPRESSION",
            "HTTP transport compression",
        ),
        (
            "max_conns_per_host",
            "PROXY-TRANSPORT-MAX-CONNS",
            "HTTP transport connection limits",
        ),
        (
            "proxy_protocol",
            "PROXY-TRANSPORT-PROXY-PROTOCOL",
            "PROXY protocol to upstreams",
        ),
    ];
    for (field, tracking_id, feature) in UNSUPPORTED_TRANSPORT_OPTIONS {
        if object.get(*field).is_some() {
            return Err(HttpError::NotImplemented {
                feature,
                tracking_id,
            });
        }
    }

    let tls = object
        .get("tls")
        .map(|tls| UpstreamTls::from_json(tls, &format!("{transport_path}.tls")))
        .transpose()?
        .map(Arc::new);
    Ok(tls)
}

/// A Unix-socket upstream with TLS has no dial host for SNI/verification, so it must configure
/// either `server_name` or `insecure_skip_verify`. Fail at config load instead of at handshake
/// time (Caddy fails the first request with "either ServerName or InsecureSkipVerify must be
/// specified").
fn validate_unix_tls(upstreams: &[Arc<Upstream>], tls: &UpstreamTls, path: &str) -> HttpResult<()> {
    if tls.insecure_skip_verify() || tls.server_name().is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    if upstreams.iter().any(|upstream| {
        matches!(
            upstream.transport(),
            crate::upstream::Transport::Unix { .. }
        )
    }) {
        return Err(invalid(
            &format!("{path}.transport.tls"),
            "a Unix-socket upstream with `transport.tls` requires `server_name` (or \
             `insecure_skip_verify`) because the socket has no host name for SNI/verification",
        ));
    }
    let _ = (upstreams, path);
    Ok(())
}

/// Parse Caddy's `health_checks` object into active and passive configuration.
///
/// Caddy's JSON shape is `health_checks.active` / `health_checks.passive`. The pre-T-PROXY-021
/// scaffold parsed top-level `health_uri`/`health_interval`/... keys; those are not Caddy fields.
/// A stray top-level `fail_duration` (also not a Caddy handler field) is likewise ignored, as
/// Caddy's JSON loader ignores unknown fields. Passive-health timing now lives under
/// `health_checks.passive.fail_duration`.
fn parse_health_checks(
    value: Option<&Value>,
    path: &str,
) -> HttpResult<(Option<Arc<HealthCheck>>, Option<PassiveHealth>)> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`health_checks` must be an object"))?;
    let active = object
        .get("active")
        .map(|active| HealthCheck::from_json(active, &format!("{path}.active")))
        .transpose()?
        .flatten()
        .map(Arc::new);
    let passive = object
        .get("passive")
        .map(|passive| PassiveHealth::from_json(passive, &format!("{path}.passive")))
        .transpose()?;
    Ok((active, passive))
}

/// The handler factory installed in the HTTP router builder.
pub fn handler_factory() -> CustomHandlerFactory {
    Arc::new(|value: &Value, path: &str| {
        let name = value.get("handler").and_then(Value::as_str);
        if name == Some("reverse_proxy") {
            Ok(Some(Arc::new(ReverseProxyHandler::from_json(value, path)?)))
        } else {
            Ok(None)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_http::Request;
    use http::Method;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    /// Upstream that echoes the interesting parts of the request it received.
    async fn spawn_echo_upstream() -> String {
        spawn_upstream(
            move |request: hyper::Request<hyper::body::Incoming>| async move {
                let header = |name: &str| {
                    request
                        .headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing")
                        .to_string()
                };
                let body = format!(
                    "path={}\nproto={}\nhost={}\nxff={}\nxfh={}\nconnection={}\nte={}",
                    request.uri().path(),
                    header("x-forwarded-proto"),
                    header("host"),
                    header("x-forwarded-for"),
                    header("x-forwarded-host"),
                    header("connection"),
                    header("te"),
                );
                let response = hyper::Response::builder()
                    .status(200)
                    .header("x-upstream", "echo")
                    .header("set-cookie", "a=1")
                    .header("set-cookie", "b=2")
                    .header("alt-svc", "h3=\":443\"")
                    .header("connection", "x-hop")
                    .header("x-hop", "drop-me");
                Ok::<_, Infallible>(
                    response
                        .body(Full::new(Bytes::from(body)))
                        .expect("response"),
                )
            },
        )
        .await
    }

    /// Upstream that always answers with a fixed status and body.
    async fn spawn_status_upstream(status: u16, body: &'static str) -> String {
        spawn_upstream(
            move |_request: hyper::Request<hyper::body::Incoming>| async move {
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(status)
                        .header("x-upstream", status.to_string())
                        .body(Full::new(Bytes::from(body)))
                        .expect("response"),
                )
            },
        )
        .await
    }

    async fn spawn_upstream<F, Fut>(serve: F) -> String
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<hyper::Response<Full<Bytes>>, Infallible>>
            + Send
            + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let serve = serve.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let serve = serve.clone();
                        async move { serve(request).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    /// Upstream that accepts a connection and closes it without responding (not a dial error).
    async fn spawn_broken_upstream() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        (address.to_string(), connections)
    }

    fn build_handler(value: Value) -> ReverseProxyHandler {
        ReverseProxyHandler::from_json(&value, "handler").unwrap()
    }

    fn handler(dial: &str) -> ReverseProxyHandler {
        build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "headers": {
                "request": {"set": {"X-Added": ["yes"]}},
                "response": {"set": {"X-Proxy": ["caddy-rs"]}}
            }
        }))
    }

    fn get_request(path: &str, remote: Option<&str>) -> Request {
        let mut request = Request::new(Method::GET, path.parse().unwrap());
        request.remote_addr = remote.map(|remote| remote.parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
    }

    fn body_text(response: &Response) -> String {
        String::from_utf8(response.body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn forwards_request_preserving_host_and_forwarded_headers() {
        let dial = spawn_echo_upstream().await;
        let handler = handler(&dial);
        let mut request = get_request("/hello?x=1", Some("203.0.113.7:5555"));
        request
            .headers
            .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-proto", "https".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-host", "spoofed.example".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        let body = body_text(&response);
        assert!(body.contains("path=/hello"), "{body}");
        assert!(body.contains("proto=http"), "{body}");
        // Caddy forwards the client Host unchanged rather than the dial address.
        assert!(body.contains("host=example.com"), "{body}");
        // Untrusted peers cannot inject X-Forwarded-* values.
        assert!(body.contains("xff=203.0.113.7"), "{body}");
        assert!(body.contains("xfh=example.com"), "{body}");
        assert_eq!(response.headers["x-proxy"], "caddy-rs");
        assert_eq!(response.headers["x-upstream"], "echo");
        assert_eq!(response.headers[http::header::VIA], "1.1 Caddy");
        assert_eq!(
            response.headers.get_all("set-cookie").iter().count(),
            2,
            "multi-value headers preserved"
        );
    }

    #[tokio::test]
    async fn trusted_proxy_values_are_retained() {
        let dial = spawn_echo_upstream().await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "trusted_proxies": ["203.0.113.0/24"]
        }));
        let mut request = get_request("/", Some("203.0.113.7:5555"));
        request
            .headers
            .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-proto", "https".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-host", "prior.example".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("xff=198.51.100.9, 203.0.113.7"), "{body}");
        assert!(body.contains("proto=https"), "{body}");
        assert!(body.contains("xfh=prior.example"), "{body}");
    }

    #[tokio::test]
    async fn hop_by_hop_headers_are_stripped_and_via_is_added() {
        let dial = spawn_echo_upstream().await;
        let handler = handler(&dial);
        let mut request = get_request("/", Some("203.0.113.7:5555"));
        request
            .headers
            .insert(http::header::CONNECTION, "x-custom".parse().unwrap());
        request
            .headers
            .insert("x-custom", "drop-me".parse().unwrap());
        request
            .headers
            .insert(http::header::TE, "trailers".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("connection=missing"), "{body}");
        assert!(body.contains("te=trailers"), "{body}");
        // Hop-by-hop response headers (and headers named by Connection) are stripped.
        assert!(!response.headers.contains_key("alt-svc"));
        assert!(!response.headers.contains_key("connection"));
        assert!(!response.headers.contains_key("x-hop"));
        assert!(response.headers.contains_key("x-upstream"));
    }

    #[tokio::test]
    async fn header_up_host_override_wins() {
        let dial = spawn_echo_upstream().await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "headers": {"request": {"set": {"Host": ["override.example"]}}}
        }));
        let request = get_request("/", Some("203.0.113.7:5555"));
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert!(body_text(&response).contains("host=override.example"));
    }

    #[tokio::test]
    async fn response_matching_retry_match_retries_to_next_upstream() {
        let bad = spawn_status_upstream(502, "bad").await;
        let good = spawn_status_upstream(200, "good").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": bad}, {"dial": good}],
            "load_balancing": {
                "retries": 1,
                "retry_match": [{"status": [502, 503]}]
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_text(&response), "good");
        assert_eq!(response.headers["x-upstream"], "200");
    }

    #[tokio::test]
    async fn non_matching_response_passes_through() {
        let upstream = spawn_status_upstream(500, "upstream-error").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "load_balancing": {
                "retries": 2,
                "retry_match": [{"status": [502, 503]}]
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body_text(&response), "upstream-error");
    }

    #[tokio::test]
    async fn retry_match_combines_request_and_response_matchers() {
        let upstream = spawn_status_upstream(502, "retried").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "load_balancing": {
                "retries": 1,
                "retry_match": [{"status": [502], "method": ["POST"]}]
            }
        }));
        // GET does not match the request matcher, so the 502 passes through with its body.
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(body_text(&response), "retried");
    }

    #[tokio::test]
    async fn exhausted_response_retry_preserves_upstream_status() {
        let upstream = spawn_status_upstream(503, "unavailable").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "load_balancing": {
                "retries": 1,
                "retry_match": [{"status": [503]}]
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        // Caddy surfaces the upstream status, not a generic 502.
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn request_only_retry_match_does_not_retry_responses() {
        let upstream = spawn_status_upstream(200, "ok").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "load_balancing": {
                "retries": 2,
                "try_interval": 1_000_000,
                "retry_match": [{"method": ["GET"]}]
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        // A request-only matcher set gates transport retries only (Caddy semantics); it must not
        // turn every matching response into a retry.
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_text(&response), "ok");
    }

    #[tokio::test]
    async fn post_transport_error_is_not_retried_by_default() {
        let (dial, connections) = spawn_broken_upstream().await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "load_balancing": {"retries": 2, "try_interval": 1_000_000}
        }));
        let mut request = Request::new(Method::POST, "/".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "non-dial transport errors must not be retried for POST without retry_match"
        );
    }

    #[tokio::test]
    async fn post_transport_error_is_retried_when_retry_match_matches() {
        let (dial, connections) = spawn_broken_upstream().await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "load_balancing": {
                "retries": 2,
                "try_interval": 1_000_000,
                "retry_match": [{"method": ["POST"]}]
            }
        }));
        let mut request = Request::new(Method::POST, "/".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            connections.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "matching retry_match should retry the transport error (1 attempt + 2 retries)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proxies_over_unix_socket_upstream() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("upstream.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(
                        |request: hyper::Request<hyper::body::Incoming>| async move {
                            let body = format!(
                                "unix path={} host={}",
                                request.uri().path(),
                                request
                                    .headers()
                                    .get(http::header::HOST)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or("missing")
                            );
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-transport", "unix")
                                    .body(Full::new(Bytes::from(body)))
                                    .expect("response"),
                            )
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let dial = format!("unix/{}", socket.display());
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}]
        }));
        let request = get_request("/over-unix?q=1", Some("203.0.113.7:5555"));
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "unix");
        let body = body_text(&response);
        assert!(body.contains("unix path=/over-unix"), "{body}");
        assert!(body.contains("host=example.com"), "{body}");
    }

    #[tokio::test]
    async fn unreachable_upstream_returns_502() {
        // Reserve a port by binding then dropping; the port is almost certainly closed afterwards.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "load_balancing": {"retries": 1, "try_interval": 1_000_000}
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn factory_builds_reverse_proxy_and_declines_others() {
        let factory = handler_factory();
        let built = factory(
            &serde_json::json!({"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:8080"}]}),
            "handler",
        )
        .unwrap();
        assert!(built.is_some());
        let declined = factory(
            &serde_json::json!({"handler": "static_response"}),
            "handler",
        )
        .unwrap();
        assert!(declined.is_none());
    }

    #[test]
    fn accepts_unix_dial_in_configuration() {
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "unix//run/app.sock"}]
        }));
        assert_eq!(handler.upstreams().len(), 1);
        assert_eq!(handler.upstreams()[0].dial, "unix//run/app.sock");
    }

    #[test]
    fn rejects_invalid_trusted_proxies() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "trusted_proxies": ["not-an-ip"]
            }),
            "handler",
        )
        .err()
        .expect("invalid trusted_proxies must fail");
        assert!(error.to_string().contains("trusted_proxies"), "{error}");
    }

    #[test]
    fn rejects_http2_upstream_transport() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "transport": {"protocol": "http", "versions": ["h2c", "2"]}
            }),
            "handler",
        )
        .err()
        .expect("h2c upstream transport must be rejected");
        assert!(error.to_string().contains("PROXY-H2-UPSTREAM"));
    }

    // ---- TLS upstream tests -------------------------------------------------------------

    const TLS_CERT_PEM: &str = include_str!("../testdata/tls/localhost-cert.pem");
    const TLS_KEY_PEM: &str = include_str!("../testdata/tls/localhost-key.pem");
    const TLS_UNRELATED_CERT_PEM: &str = include_str!("../testdata/tls/unrelated-cert.pem");

    fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let certificates = crate::tls::parse_pem_certificates(TLS_CERT_PEM.as_bytes()).unwrap();
        let key = crate::tls::parse_pem_private_key(TLS_KEY_PEM.as_bytes()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    /// Spawn a TLS upstream over TCP; `respond` decides the response for each request.
    async fn spawn_tls_upstream<F, Fut>(respond: F) -> String
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<hyper::Response<Full<Bytes>>, Infallible>>
            + Send
            + 'static,
    {
        let acceptor = tls_acceptor();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let respond = respond.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request| {
                        let respond = respond.clone();
                        async move { respond(request).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    async fn spawn_tls_echo_upstream(status: u16) -> String {
        spawn_tls_upstream(
            move |request: hyper::Request<hyper::body::Incoming>| async move {
                let body = format!(
                    "tls path={} host={}",
                    request.uri().path(),
                    request
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing")
                );
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(status)
                        .header("x-transport", "tls")
                        .body(Full::new(Bytes::from(body)))
                        .expect("response"),
                )
            },
        )
        .await
    }

    fn write_tls_root(directory: &tempfile::TempDir, pem: &str) -> String {
        let path = directory.path().join("root-ca.pem");
        std::fs::write(&path, pem).unwrap();
        path.display().to_string()
    }

    #[tokio::test]
    async fn proxies_over_tls_upstream_with_explicit_root() {
        let dial = spawn_tls_echo_upstream(200).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_tls_root(&directory, TLS_CERT_PEM);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {
                "protocol": "http",
                "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
            }
        }));
        let Outcome::Respond(response) = handler
            .handle(get_request("/tls?x=1", Some("203.0.113.7:5555")))
            .await
            .unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "tls");
        let body = body_text(&response);
        assert!(body.contains("tls path=/tls"), "{body}");
        assert!(body.contains("host=example.com"), "{body}");
        assert_eq!(response.headers[http::header::VIA], "1.1 Caddy");
    }

    #[tokio::test]
    async fn untrusted_tls_certificate_is_rejected() {
        let dial = spawn_tls_echo_upstream(200).await;
        let directory = tempfile::tempdir().unwrap();
        // Trust a different self-signed certificate, so the upstream certificate cannot chain.
        let root = write_tls_root(&directory, TLS_UNRELATED_CERT_PEM);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {
                "protocol": "http",
                "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxy error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn self_signed_upstream_is_not_trusted_by_default_platform_roots() {
        // The fixture is a self-signed certificate that no platform trust store contains. When a
        // platform bundle exists, the default trust policy must reject it; without any loadable
        // bundle the handler fails loudly at config time (both are acceptable loud outcomes).
        let dial = spawn_tls_echo_upstream(200).await;
        let handler = match ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "transport": {"protocol": "http", "tls": {}}
            }),
            "handler",
        ) {
            Ok(handler) => handler,
            Err(error) => {
                let error = error.to_string();
                assert!(
                    error.contains("no TLS trust roots"),
                    "expected either a trust failure or a loud missing-roots error: {error}"
                );
                return;
            }
        };
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxy error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn insecure_skip_verify_allows_self_signed_upstream() {
        let dial = spawn_tls_echo_upstream(200).await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {
                "protocol": "http",
                "tls": {"insecure_skip_verify": true, "server_name": "localhost"}
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "tls");
    }

    #[tokio::test]
    async fn insecure_skip_verify_absent_rejects_self_signed_upstream() {
        // Root trust points at the unrelated certificate on purpose: only explicit
        // `insecure_skip_verify: true` may bypass verification.
        let dial = spawn_tls_echo_upstream(200).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_tls_root(&directory, TLS_UNRELATED_CERT_PEM);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {
                "protocol": "http",
                "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
            }
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected proxy error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn health_check_over_tls_upstream() {
        let healthy = spawn_tls_echo_upstream(200).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_tls_root(&directory, TLS_CERT_PEM);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": healthy}],
            "transport": {
                "protocol": "http",
                "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
            },
            "health_checks": {"active": {"uri": "/health"}}
        }));
        let check = handler.health_check().expect("active checks configured");
        assert!(
            check
                .check_once(handler.client(), &handler.upstreams()[0])
                .await,
            "active health check should complete over TLS"
        );

        let failing = spawn_tls_echo_upstream(500).await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": failing}],
            "transport": {
                "protocol": "http",
                "tls": {"insecure_skip_verify": true, "server_name": "localhost"}
            },
            "health_checks": {"active": {"uri": "/health"}}
        }));
        let check = handler.health_check().expect("active checks configured");
        assert!(
            !check
                .check_once(handler.client(), &handler.upstreams()[0])
                .await,
            "failing TLS upstream must fail the probe"
        );
    }

    #[test]
    fn unix_socket_tls_upstream_requires_server_name() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_tls_root(&directory, TLS_CERT_PEM);
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "unix//tmp/upstream.sock"}],
                "transport": {
                    "protocol": "http",
                    "tls": {"root_ca_pem_files": [root]}
                }
            }),
            "handler",
        )
        .err()
        .expect("Unix socket TLS without server_name must fail at config load");
        assert!(error.to_string().contains("server_name"), "{error}");

        // With an explicit server name the configuration is accepted.
        let root = write_tls_root(&directory, TLS_CERT_PEM);
        ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "unix//tmp/upstream.sock"}],
                "transport": {
                    "protocol": "http",
                    "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
                }
            }),
            "handler",
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proxies_over_tls_unix_socket_upstream() {
        let acceptor = tls_acceptor();
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("tls-upstream.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(
                        |request: hyper::Request<hyper::body::Incoming>| async move {
                            let body = format!("unix-tls path={}", request.uri().path());
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-transport", "unix-tls")
                                    .body(Full::new(Bytes::from(body)))
                                    .expect("response"),
                            )
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });

        let root_dir = tempfile::tempdir().unwrap();
        let root = write_tls_root(&root_dir, TLS_CERT_PEM);
        let dial = format!("unix/{}", socket.display());
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {
                "protocol": "http",
                "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
            }
        }));
        let Outcome::Respond(response) = handler
            .handle(get_request("/over-unix-tls", Some("203.0.113.7:5555")))
            .await
            .unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "unix-tls");
        assert!(body_text(&response).contains("unix-tls path=/over-unix-tls"));
    }

    #[test]
    fn h1_only_transport_versions_are_accepted_with_tls() {
        ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8443"}],
                "transport": {
                    "protocol": "http",
                    "versions": ["1.1"],
                    "tls": {"insecure_skip_verify": true}
                }
            }),
            "handler",
        )
        .unwrap();
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8443"}],
                "transport": {"protocol": "http", "versions": ["2"], "tls": {}}
            }),
            "handler",
        )
        .err()
        .expect("h2 upstream transport must stay unsupported");
        assert!(error.to_string().contains("PROXY-H2-UPSTREAM"), "{error}");
    }

    #[test]
    fn unsupported_transport_options_fail_loudly() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8443"}],
                "transport": {"protocol": "http", "keep_alive": {"enabled": false}}
            }),
            "handler",
        )
        .err()
        .expect("unsupported transport option must fail");
        assert!(
            error.to_string().contains("PROXY-TRANSPORT-KEEPALIVE"),
            "{error}"
        );
    }

    #[test]
    fn parses_trusted_proxy_cidr_ranges() {
        let range = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(range.contains("10.1.2.3".parse().unwrap()));
        assert!(!range.contains("11.1.2.3".parse().unwrap()));
        let range = IpNet::parse("2001:db8::/32").unwrap();
        assert!(range.contains("2001:db8::1".parse().unwrap()));
        assert!(!range.contains("2001:db9::1".parse().unwrap()));
        let single = IpNet::parse("192.0.2.10").unwrap();
        assert!(single.contains("192.0.2.10".parse().unwrap()));
        assert!(!single.contains("192.0.2.11".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("10.0.0.0/9")
            .unwrap()
            .contains("10.100.0.1".parse().unwrap()));
    }

    #[test]
    fn hop_by_hop_strips_connection_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "X-Hop, keep-alive".parse().unwrap(),
        );
        headers.insert("x-hop", "1".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-keep", "yes".parse().unwrap());
        let stripped = strip_hop_by_hop(&headers);
        assert!(!stripped.contains_key("connection"));
        assert!(!stripped.contains_key("x-hop"));
        assert!(!stripped.contains_key("keep-alive"));
        assert_eq!(stripped["x-keep"], "yes");
    }

    #[test]
    fn parses_health_checks_active_and_passive_configuration() {
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "health_checks": {
                "active": {
                    "uri": "/healthz?probe=1",
                    "method": "HEAD",
                    "headers": {"X-Probe": ["yes"]},
                    "body": "ping",
                    "interval": 2_000_000_000u64,
                    "timeout": 500_000_000u64,
                    "passes": 2,
                    "fails": 3,
                    "expect_status": 204
                },
                "passive": {
                    "fail_duration": 10_000_000_000u64,
                    "max_fails": 4,
                    "unhealthy_status": [502, 5],
                    "unhealthy_latency": 1_000_000_000u64,
                    "unhealthy_request_count": 8
                }
            }
        }));
        let active = handler.health_check().expect("active checks configured");
        assert_eq!(active.uri, "/healthz?probe=1");
        assert_eq!(active.method, http::Method::HEAD);
        assert_eq!(active.passes, 2);
        assert_eq!(active.fails, 3);
        assert_eq!(active.expected_status, Some(204));
        assert_eq!(
            active.headers,
            vec![("X-Probe".to_string(), "yes".to_string())]
        );

        let passive = handler
            .passive_health()
            .expect("passive checks configured")
            .config();
        assert_eq!(passive.fail_duration, Duration::from_secs(10));
        assert_eq!(passive.max_fails, 4);
        assert_eq!(passive.unhealthy_status, vec![502, 5]);
        assert_eq!(passive.unhealthy_latency, Duration::from_secs(1));
        assert_eq!(passive.unhealthy_request_count, 8);
    }

    #[test]
    fn active_health_checks_without_uri_are_disabled() {
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "health_checks": {"active": {"interval": 1_000_000_000u64}}
        }));
        assert!(handler.health_check().is_none());
        assert!(handler.spawn_health_checks().is_none());
    }

    #[test]
    fn spawn_health_checks_is_exposed_for_the_runtime() {
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "health_checks": {"active": {"uri": "/health"}}
        }));
        assert!(handler.health_check().is_some());
        // Creating the scheduler requires a Tokio runtime, so only assert the API is reachable in
        // an async test below; here the synchronous accessor must at least be present.
        assert!(handler.passive_health().is_none());
    }

    #[test]
    fn legacy_top_level_health_keys_are_ignored() {
        // Not Caddy JSON: health options belong under `health_checks`. Unknown handler fields are
        // ignored, matching Caddy's JSON loader.
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "health_uri": "/health",
            "health_interval": 1_000_000_000u64,
            "fail_duration": 5_000_000_000u64
        }));
        assert!(handler.health_check().is_none());
        assert!(handler.passive_health().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_health_checks_starts_and_stops_a_checker() {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let dial = spawn_upstream(move |_request| {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::new()))
                        .expect("response"),
                )
            }
        });
        let dial = dial.await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "health_checks": {"active": {"uri": "/health", "interval": 1_000_000_000u64}}
        }));
        let scheduler = handler
            .spawn_health_checks()
            .expect("scheduler for configured active checks");
        for _ in 0..100 {
            if hits.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "scheduler should probe configured upstreams"
        );
        scheduler.shutdown().await;
        let after_shutdown = hits.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            after_shutdown,
            "shutdown must stop the health-check task"
        );
    }

    #[tokio::test]
    async fn passive_health_removes_failing_upstream_from_rotation() {
        let bad = spawn_status_upstream(502, "bad").await;
        let good = spawn_status_upstream(200, "good").await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": bad}, {"dial": good}],
            "load_balancing": {"selection_policy": {"policy": "first"}},
            "health_checks": {
                "passive": {
                    "fail_duration": 10_000_000_000u64,
                    "max_fails": 1,
                    "unhealthy_status": [502]
                }
            }
        }));
        // First request hits the first upstream, which fails its passive health check.
        let Outcome::Respond(first) = handler.handle(get_request("/", None)).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(first.status, StatusCode::BAD_GATEWAY);
        let passive = handler.passive_health().expect("passive configured");
        let bad_dial = handler.upstreams()[0].dial.clone();
        assert!(!passive.is_healthy(&bad_dial, std::time::Instant::now()));
        assert!(
            !passive.is_available(&bad_dial, std::time::Instant::now(), 0),
            "failing upstream must leave rotation"
        );

        // Subsequent requests skip it and reach the healthy upstream.
        let Outcome::Respond(second) = handler.handle(get_request("/", None)).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(second.status, StatusCode::OK);
        assert_eq!(body_text(&second), "good");
    }

    #[tokio::test]
    async fn passive_health_counts_transport_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial.clone()}],
            "health_checks": {"passive": {"fail_duration": 10_000_000_000u64, "max_fails": 1}}
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/", None)).await.unwrap()
        else {
            panic!("expected error response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        let passive = handler.passive_health().expect("passive configured");
        assert_eq!(passive.failures(&dial, std::time::Instant::now()), 1);
        assert!(!passive.is_healthy(&dial, std::time::Instant::now()));
    }
}
