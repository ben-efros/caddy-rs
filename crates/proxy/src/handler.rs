//! The `reverse_proxy` handler.
//!
//! Header handling follows Caddy's `prepareRequest` / `addForwardedHeaders` semantics:
//!
//! * The client's `Host` header is forwarded unchanged (Caddy only rewrites it through `header_up`
//!   operations or a transport-level host).
//! * Hop-by-hop headers are stripped (including headers named by the `Connection` header).
//! * `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set from the connection.
//!   Prior values are only trusted when the peer is in `trusted_proxies`.
//! * `Via` is appended to the upstream request (`<client proto> Caddy`) and to the upstream
//!   response (`<upstream proto> Caddy`), matching Caddy.
//! * Server-level `trusted_proxies` is consumed through the `trusted_proxy`/`client_ip` request
//!   variables set by the server (`crate::trusted_proxies`); the handler-level `trusted_proxies`
//!   list still works and is unioned with the server decision, like Caddy.
//!
//! Upstreams may be `host:port` TCP dials or Unix sockets (`unix//path`); the client selects the
//! transport from the outbound URI.
//!
//! Request bodies follow the `T-PROXY-039` capability policy: handlers that can retry
//! (`retries`/`try_duration`) or that run `handle_response` buffer the body once and replay it,
//! while every other handler streams the body exactly once (`Request::take_body`). A retry that
//! would require replaying an already-streamed body fails loudly with a 502 instead of forwarding
//! an empty body.
//!
//! For HTTP/2-capable transports the outbound URI authority is the original request `Host` (so
//! HTTP/2 `:authority` matches Caddy/Go) while a per-upstream client connector still dials the
//! configured upstream target; no separate `Host` field is forwarded on h2.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
#[cfg(test)]
use http_body_util::Full;
use serde_json::Value;

use hyper_util::rt::TokioIo;

use caddy_rs_http::{
    body::{Body, RequestBody, StreamingBody, StreamingResponse},
    requested_upgrade_type, CustomHandlerFactory, Error as HttpError, Handler, Outcome, Request,
    Response, Result as HttpResult, SharedHandler, StreamingOutcome, Tunnel, UpgradedResponse,
};

use crate::balancer::{self, Balancer};
use crate::client::{build_upstream_client, UpstreamClient};
use crate::fastcgi::{FastCgiError, FastCgiTransport};
use crate::forward_auth::{HandleResponse, HandleResponseResult, RequestRewrite};
use crate::health::{HealthCheck, HealthCheckScheduler};
use crate::passive::PassiveHealth;
use crate::retry::RetryMatch;
use crate::template::{HeaderOps, TemplateContext};
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
    /// The upstream answered 101 but the upgrade handshake could not be completed.
    #[error("upstream protocol upgrade failed: {0}")]
    Upgrade(String),
    /// The upstream switched protocols, but the buffered handler path cannot carry a tunnel.
    #[error(
        "upstream switched protocols but the buffered reverse_proxy path cannot tunnel \
         (T-PROXY-032)"
    )]
    UpgradeNotSupported,
    /// FastCGI transport failure (dial, protocol, timeout or body error).
    #[error("fastcgi transport error: {0}")]
    FastCgi(#[from] FastCgiError),
}

impl ProxyError {
    /// Whether this failure happened before any bytes of the request reached the upstream.
    ///
    /// A dial failure is always safe to retry, even for non-idempotent methods (Caddy's
    /// `DialError` rule); other transport errors are only retried when `retry_match` opts in.
    fn is_dial_error(&self) -> bool {
        match self {
            ProxyError::Client(error) => error.is_connect(),
            ProxyError::FastCgi(error) => error.is_connect(),
            _ => false,
        }
    }

    /// A specific HTTP status Caddy would surface for this failure (e.g. 411 for a FastCGI
    /// request whose body has no known length), when it is not the generic 502.
    fn explicit_status(&self) -> Option<StatusCode> {
        match self {
            ProxyError::FastCgi(error) => error.status(),
            _ => None,
        }
    }

    /// Whether this is the "upgrade needs the streaming path" error.
    fn is_upgrade_not_supported(&self) -> bool {
        matches!(self, ProxyError::UpgradeNotSupported)
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

/// One proxied upstream response whose body is still streaming.
struct ForwardedStreamingResponse {
    status: StatusCode,
    /// Time until the upstream sent its response headers (Caddy's roundtrip duration).
    latency: Duration,
    headers: HeaderMap,
    body: StreamingBody,
}

/// One proxied upstream response that switched protocols (`101 Switching Protocols`).
struct ForwardedUpgrade {
    status: StatusCode,
    /// Time until the upstream sent its response headers (Caddy's roundtrip duration).
    latency: Duration,
    headers: HeaderMap,
    /// The upgraded upstream connection.
    tunnel: Tunnel,
}

/// A forwarded upstream response: a normal (streaming) response or a protocol switch.
enum Forwarded {
    Streaming(ForwardedStreamingResponse),
    Upgrade(ForwardedUpgrade),
}

/// How often Caddy flushes a proxied response body (`reverse_proxy.flush_interval`).
///
/// Caddy's sentinel `-1` (the default) means "flush immediately after every write". The streaming
/// path in caddy-rs always flushes each chunk as soon as it arrives (equivalent to `-1`); a
/// positive interval is accepted for configuration compatibility but does not coalesce chunks yet.
/// See DIV-0060.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlushInterval {
    /// Flush after every frame (Caddy's `-1` default).
    #[default]
    Immediate,
    /// A positive flush interval from configuration (accepted; streaming flushes immediately).
    Interval(Duration),
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

/// Live per-upstream counters in Caddy's `GET /reverse_proxy/upstreams` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// Upstream dial address (`host:port` or `unix/...`).
    pub address: String,
    /// Proxy attempts sent to this upstream since it was configured.
    pub num_requests: u64,
    /// Failed attempts (including passive-health strikes) for this upstream.
    pub fails: u64,
}

/// Collects the live [`ReverseProxyHandler`] instances built for one configuration generation.
///
/// The server runtime builds a fresh sink for every apply and installs it as the active source for
/// `GET /reverse_proxy/upstreams` only after the generation was applied successfully, so values
/// always describe the active generation and a reload swaps them atomically. Handlers are held
/// weakly: when a retired generation's routers are dropped, its counters disappear.
#[derive(Default)]
pub struct UpstreamStatusSink {
    handlers: Mutex<Vec<Weak<ReverseProxyHandler>>>,
}

impl std::fmt::Debug for UpstreamStatusSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        formatter
            .debug_struct("UpstreamStatusSink")
            .field("handlers", &handlers.len())
            .finish()
    }
}

impl UpstreamStatusSink {
    /// Create an empty sink (shared by the server runtime and the handler factory).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Track a handler built for this generation (kept weakly).
    pub fn register(&self, handler: &Arc<ReverseProxyHandler>) {
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        handlers.push(Arc::downgrade(handler));
    }

    /// Snapshot the live counters, merging handlers that share an upstream address (Caddy keeps
    /// one global pool per address; caddy-rs keeps per-handler counters, so duplicates are summed).
    pub fn snapshot(&self) -> Vec<UpstreamStatus> {
        let mut handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        handlers.retain(|handler| handler.strong_count() > 0);
        let mut merged: std::collections::BTreeMap<String, UpstreamStatus> =
            std::collections::BTreeMap::new();
        for handler in handlers.iter() {
            let Some(handler) = handler.upgrade() else {
                continue;
            };
            for status in handler.upstream_statuses() {
                let entry = merged
                    .entry(status.address.clone())
                    .or_insert(UpstreamStatus {
                        address: status.address.clone(),
                        num_requests: 0,
                        fails: 0,
                    });
                entry.num_requests += status.num_requests;
                entry.fails += status.fails;
            }
        }
        merged.into_values().collect()
    }
}

/// Reverse proxy handler configuration and runtime.
pub struct ReverseProxyHandler {
    /// One client per upstream. Each connector dials its bound upstream target, so the request URI
    /// authority can carry the client's Host (HTTP/2 `:authority` parity) without affecting which
    /// target is dialed.
    clients: Vec<UpstreamClient>,
    /// HTTP/1.1-only companion clients used for protocol-upgrade (WebSocket) requests when the
    /// configured upstream transport prefers HTTP/2 (ALPN h2 or h2c). HTTP/1.1 upgrades cannot be
    /// carried over HTTP/2, and Caddy likewise disables ALPN h2 for upgradable connections.
    upgrade_clients: Option<Vec<UpstreamClient>>,
    /// Parsed transport configuration (TLS client config and HTTP version policy).
    transport: TransportConfig,
    upstreams: Vec<Arc<Upstream>>,
    balancer: Box<dyn Balancer>,
    request_header_ops: HeaderOps,
    response_header_ops: HeaderOps,
    rewrite: Option<RequestRewrite>,
    handle_response: HandleResponse,
    retries: u32,
    try_duration: Duration,
    try_interval: Duration,
    health_check: Option<Arc<HealthCheck>>,
    passive: Option<PassiveHealth>,
    retry_match: RetryMatch,
    trusted_proxies: Vec<IpNet>,
    flush_interval: FlushInterval,
}

impl ReverseProxyHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "reverse_proxy handler must be an object"))?;

        // Fail closed on handler fields Caddy implements but this build does not: silently
        // ignoring them could skip security-relevant behaviour (see T-PROXY-037).
        audit_unsupported_handler_fields(object, path)?;

        // `transport` applies to every upstream of the handler (Caddy's transport is per-handler,
        // not per-upstream). TLS trust and HTTP version configuration are built here so invalid
        // configuration surfaces as located errors instead of per-request transport failures.
        let transport = parse_transport(object.get("transport"), path)?;
        let tls = transport.tls.clone();

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
            let max_requests = match upstream.get("max_requests") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let max = value.as_u64().ok_or_else(|| {
                        invalid(
                            &format!("{upstream_path}.max_requests"),
                            "`max_requests` must be a non-negative integer",
                        )
                    })?;
                    Some(usize::try_from(max).map_err(|_| {
                        invalid(
                            &format!("{upstream_path}.max_requests"),
                            "`max_requests` is too large for this platform",
                        )
                    })?)
                }
            };
            // Caddy's `tls.except_ports` dials those upstream ports without TLS even though the
            // transport has a TLS configuration.
            let tls_for_upstream = tls
                .as_ref()
                .is_some_and(|tls| tls.should_use_tls(dial_port(dial)));
            let parsed = Upstream::parse_dial(dial, tls_for_upstream)
                .map_err(|message| invalid(&upstream_path, message))?
                .with_max_requests(max_requests);
            upstreams.push(Arc::new(parsed));
        }
        if let Some(tls) = &tls {
            validate_unix_tls(&upstreams, tls, path)?;
        }

        let load_balancing = object.get("load_balancing");
        let selection_policy = load_balancing.and_then(|lb| lb.get("selection_policy"));
        let balancer =
            balancer::from_selection_policy(selection_policy, &format!("{path}.load_balancing"))
                .map_err(|error| match error {
                    balancer::BalancerError::Invalid(message) => invalid(path, message),
                    balancer::BalancerError::NotImplemented {
                        feature,
                        tracking_id,
                    } => HttpError::NotImplemented {
                        feature,
                        tracking_id,
                    },
                })?;
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

        let clients = build_upstream_clients(&upstreams, &transport, path)?;
        let h2_capable = transport.alpn_h2 || transport.h2c;
        let upgrade_clients = if h2_capable {
            Some(build_upgrade_clients(&upstreams, &transport, path)?)
        } else {
            None
        };

        let header_config = parse_headers(object.get("headers"), path)?;

        let rewrite = RequestRewrite::from_json(object.get("rewrite"), &format!("{path}.rewrite"))?;
        let handle_response = HandleResponse::from_json(
            object.get("handle_response"),
            &format!("{path}.handle_response"),
        )?;

        let trusted_proxies = parse_trusted_proxies(object.get("trusted_proxies"), path)?;

        let (health_check, passive) = parse_health_checks(object.get("health_checks"), path)?;
        if transport.fastcgi.is_some() && health_check.is_some() {
            return Err(HttpError::NotImplemented {
                feature:
                    "active health checks over the FastCGI transport (the probe client is HTTP-only)",
                tracking_id: "PROXY-FASTCGI-HEALTH",
            });
        }

        let flush_interval = parse_flush_interval(
            object.get("flush_interval"),
            &format!("{path}.flush_interval"),
        )?;

        Ok(Self {
            clients,
            upgrade_clients,
            transport,
            upstreams,
            balancer,
            request_header_ops: header_config.request,
            response_header_ops: header_config.response,
            rewrite,
            handle_response,
            retries,
            try_duration,
            try_interval,
            health_check,
            passive,
            retry_match,
            trusted_proxies,
            flush_interval,
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

    /// Configured response-body flush policy (`reverse_proxy.flush_interval`).
    pub fn flush_interval(&self) -> FlushInterval {
        self.flush_interval
    }

    /// The outbound client (TLS-aware), exposed for crate-level health-check tests.
    #[cfg(test)]
    pub(crate) fn client(&self) -> &UpstreamClient {
        &self.clients[0]
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
            let targets = self
                .upstreams
                .iter()
                .cloned()
                .zip(self.clients.iter().cloned())
                .collect();
            HealthCheckScheduler::spawn(Arc::clone(check), targets)
        })
    }

    /// Send the upstream request and return the response with its body still streaming.
    ///
    /// No body bytes are read here: only the response head is awaited. The returned
    /// [`StreamingBody`] bridges the hyper upstream body, preserves chunk boundaries and
    /// terminates with an error if the upstream fails mid-stream. Dropping it cancels the
    /// upstream transfer.
    async fn forward_streaming(
        &self,
        upstream: &Arc<Upstream>,
        request: &Request,
        body: RequestBody,
    ) -> Result<Forwarded, ProxyError> {
        // `forward_auth` (and any configured `rewrite`) changes only the auth sub-request: the
        // original request is untouched so later handlers still see the client's method/URI/body.
        let (method, path_and_query) = match &self.rewrite {
            Some(rewrite) => rewrite.prepare(request),
            None => (
                request.method.clone(),
                request
                    .uri
                    .path_and_query()
                    .map(|value| value.as_str())
                    .unwrap_or("/")
                    .to_string(),
            ),
        };
        // Canonical `forward_auth` rewrites the method to GET, which drops the sub-request body
        // (the original request body stays untouched for later handlers).
        let body = match &self.rewrite {
            Some(rewrite) if rewrite.drops_body() => RequestBody::empty(),
            _ => body,
        };
        if let Some(fastcgi) = &self.transport.fastcgi {
            let started = std::time::Instant::now();
            let response = fastcgi
                .forward(upstream, request, method, &path_and_query, body)
                .await?;
            let latency = started.elapsed();
            return Ok(Forwarded::Streaming(ForwardedStreamingResponse {
                status: response.status,
                latency,
                headers: self.response_headers(&response.headers, Version::HTTP_11),
                body: response.body,
            }));
        }
        let mut headers = self.outbound_headers(request, upstream)?;
        let url = if self.upstream_h2_capable(upstream) {
            // HTTP/2 `:authority` parity with Caddy/Go: use the original request Host (or a
            // header_up Host override) as the URI authority; the bound per-upstream connector
            // still dials the configured target. The Host field is not forwarded separately.
            let host = headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .or_else(|| request.host().map(str::to_string))
                .unwrap_or_else(|| upstream.fallback_host().to_string());
            headers.remove(http::header::HOST);
            let scheme = if upstream.tls { "https" } else { "http" };
            format!("{scheme}://{host}{path_and_query}")
        } else {
            upstream.url(&path_and_query)
        };

        let mut outbound = hyper::Request::builder()
            .method(method)
            .uri(url)
            .body(body)
            .map_err(|error| ProxyError::Request(error.to_string()))?;
        *outbound.headers_mut() = headers;

        let started = std::time::Instant::now();
        let mut response = self
            .upstream_client(upstream, request)
            .request(outbound)
            .await?;
        let latency = started.elapsed();
        let status = response.status();
        let version = response.version();
        let response_headers = response.headers().clone();

        if status == StatusCode::SWITCHING_PROTOCOLS {
            // RFC 7230 §6.7 / Caddy's handleUpgradeResponse: the protocol the upstream selected
            // must be exactly the one the client requested (case-insensitive printable ASCII).
            let requested = requested_upgrade_type(&request.headers).ok_or_else(|| {
                ProxyError::Upgrade(
                    "upstream switched protocols but the client did not request an upgrade"
                        .to_string(),
                )
            })?;
            let selected = response_headers
                .get(http::header::UPGRADE)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .unwrap_or("");
            if selected.is_empty()
                || !selected.bytes().all(|byte| byte.is_ascii_graphic())
                || !selected.eq_ignore_ascii_case(&requested)
            {
                return Err(ProxyError::Upgrade(format!(
                    "upstream selected unexpected protocol {selected:?}; client requested                      {requested:?}"
                )));
            }

            // Take the upgraded client-side connection before consuming the response.
            let on_upgrade = hyper::upgrade::on(&mut response);
            let upgraded = on_upgrade
                .await
                .map_err(|error| ProxyError::Upgrade(error.to_string()))?;
            return Ok(Forwarded::Upgrade(ForwardedUpgrade {
                status,
                latency,
                headers: upgrade_response_headers(&response_headers),
                tunnel: Tunnel::new(TokioIo::new(upgraded)),
            }));
        }

        let body = StreamingBody::from_hyper(response.into_body());
        Ok(Forwarded::Streaming(ForwardedStreamingResponse {
            status,
            latency,
            headers: self.response_headers(&response_headers, version),
            body,
        }))
    }

    /// Send the upstream request and buffer the whole response body.
    ///
    /// This is the legacy `Handler::handle` path: the server does not consume streaming bodies
    /// yet, so the buffered API must keep returning a complete [`Response`]. The streaming path
    /// ([`Handler::handle_streaming`]) uses [`Self::forward_streaming`] directly.
    async fn forward(
        &self,
        upstream: &Arc<Upstream>,
        request: &Request,
        body: RequestBody,
    ) -> Result<ForwardedResponse, ProxyError> {
        let forwarded = match self.forward_streaming(upstream, request, body).await? {
            Forwarded::Streaming(forwarded) => forwarded,
            Forwarded::Upgrade(_) => return Err(ProxyError::UpgradeNotSupported),
        };
        let body = forwarded
            .body
            .into_bytes()
            .await
            .map_err(|error| ProxyError::Body(error.to_string()))?;
        Ok(ForwardedResponse {
            status: forwarded.status,
            latency: forwarded.latency,
            headers: forwarded.headers,
            body,
        })
    }

    /// The per-upstream client used for this request.
    ///
    /// Protocol-upgrade (WebSocket) requests go through the HTTP/1.1-only companion client when
    /// the main upstream transport prefers HTTP/2: HTTP/1.1 upgrades cannot be expressed over
    /// HTTP/2, and Caddy likewise disables ALPN h2 for upgradable connections.
    fn upstream_client(&self, upstream: &Arc<Upstream>, request: &Request) -> &UpstreamClient {
        let index = self
            .upstreams
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, upstream))
            .unwrap_or(0);
        if requested_upgrade_type(&request.headers).is_some() {
            if let Some(upgrade_clients) = &self.upgrade_clients {
                return &upgrade_clients[index];
            }
        }
        &self.clients[index]
    }

    /// Live per-upstream counters (used by the admin `/reverse_proxy/upstreams` endpoint).
    pub fn upstream_statuses(&self) -> Vec<UpstreamStatus> {
        self.upstreams
            .iter()
            .map(|upstream| UpstreamStatus {
                address: upstream.dial.clone(),
                num_requests: upstream.num_requests(),
                fails: upstream.fails(),
            })
            .collect()
    }

    /// Whether *this upstream* speaks HTTP/2 (TLS h2 only applies to TLS upstreams; h2c applies to
    /// cleartext transports).
    fn upstream_h2_capable(&self, upstream: &Upstream) -> bool {
        (self.transport.alpn_h2 && upstream.tls) || self.transport.h2c
    }

    /// Prepare the outbound request body for one proxy attempt (`T-PROXY-040`).
    ///
    /// A retry-capable handler buffers the body once before the loop and replays it; otherwise the
    /// streaming body is taken out exactly once. A second streaming attempt cannot be replayed, so
    /// it fails loudly instead of silently forwarding an empty body.
    fn attempt_body(
        &self,
        request: &mut Request,
        buffered: bool,
        stream_taken: &mut bool,
    ) -> Result<RequestBody, &'static str> {
        if buffered {
            Ok(RequestBody::buffered(request.body.clone()))
        } else if *stream_taken {
            Err(
                "request body was already streamed to an upstream and cannot be replayed for a retry",
            )
        } else {
            *stream_taken = true;
            Ok(request.take_body())
        }
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

        // Caddy forwards the client's Host unchanged. For HTTP/1.1-only transports it becomes an
        // explicit `Host` field (the URI authority is the dial target). For HTTP/2-capable
        // transports the Host is carried by the URI authority instead — hyper/HTTP2 derives
        // `:authority` from it — and no separate `Host` field is sent, matching Go's h2 client.
        if self.upstream_h2_capable(upstream) {
            headers.remove(http::header::HOST);
        } else {
            let host = request.host().unwrap_or_else(|| upstream.fallback_host());
            headers.insert(
                http::header::HOST,
                HeaderValue::from_str(host)
                    .map_err(|error| ProxyError::Request(error.to_string()))?,
            );
        }

        self.add_forwarded_headers(&mut headers, request, upstream)?;

        // After stripping hop-by-hop headers (which include `Connection` and `Upgrade`), add the
        // upgrade negotiation back so WebSocket-style handshakes reach the upstream. Caddy does
        // this after hop-by-hop removal and before `header_up` operations.
        if let Some(upgrade_type) = requested_upgrade_type(&request.headers) {
            headers.insert(
                http::header::CONNECTION,
                HeaderValue::from_static("Upgrade"),
            );
            headers.insert(
                http::header::UPGRADE,
                HeaderValue::from_str(&upgrade_type)
                    .map_err(|error| ProxyError::Request(error.to_string()))?,
            );
        }

        // Caddy appends `Via: <client proto> Caddy` to the upstream request after the forwarded
        // headers and before `header_up` operations (so user operations can still override it).
        headers.append(
            http::header::VIA,
            HeaderValue::from_str(&client_via_value(request))
                .map_err(|error| ProxyError::Request(error.to_string()))?,
        );

        // `header_up` operations are applied last and win over the implicit headers. Values are
        // templates: canonical `forward_auth` relies on `{http.request.method}` / `{http.request.uri}`
        // carrying the *original* request values to the auth service.
        let context = TemplateContext {
            request,
            response_status: None,
            response_headers: None,
            vars: Some(&request.vars),
        };
        self.request_header_ops.apply(&mut headers, &context);
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
        // Caddy formats peers through Go net.IP, which renders IPv4-mapped IPv6 addresses as
        // dotted IPv4; canonicalize so X-Forwarded-For and trust checks match (DIV-0098).
        let client_ip = remote.ip().to_canonical();
        // The server runtime sets Caddy's `trusted_proxy` var from the server-level
        // trusted_proxies; the handler-level list is unioned with it, like Caddy.
        let server_trusted = request
            .vars
            .get("trusted_proxy")
            .is_some_and(|value| value == "true");
        let trusted = server_trusted
            || self
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

    /// Apply the configured `headers.response` operations to a response header map (buffered and
    /// streaming responses share the same semantics).
    fn apply_response_headers_to(
        &self,
        headers: &mut HeaderMap,
        request: &Request,
        status: StatusCode,
        upstream_headers: &HeaderMap,
    ) {
        let snapshot = request.clone();
        let context = TemplateContext {
            request: &snapshot,
            response_status: Some(status),
            response_headers: Some(upstream_headers),
            vars: Some(&snapshot.vars),
        };
        self.response_header_ops.apply(headers, &context);
    }

    /// Caddy's `Upstream.Available()`: not actively unhealthy, below the passive failure
    /// threshold, and below the simultaneous-request limit.
    ///
    /// Caddy copies `health_checks.passive.unhealthy_request_count` into `MaxRequests` only for
    /// upstreams without an explicit `max_requests`; an explicit `max_requests` wins.
    fn upstream_available(&self, upstream: &Upstream, now: std::time::Instant) -> bool {
        if upstream.is_full() {
            return false;
        }
        match &self.passive {
            None => true,
            Some(passive) => {
                if upstream.max_requests().is_some() {
                    passive.is_healthy(&upstream.dial, now)
                } else {
                    passive.is_available(&upstream.dial, now, upstream.active_connections())
                }
            }
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

/// Reject `reverse_proxy` handler fields that Caddy implements but caddy-rs does not.
///
/// Unknown fields that Caddy also ignores are harmless (both loaders ignore them), but a field
/// with runtime meaning must never be silently dropped: that is exactly how an authentication gate
/// could appear configured while doing nothing. Each rejection names the field and the tracking
/// task.
fn audit_unsupported_handler_fields(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<()> {
    const UNSUPPORTED: &[(&str, &str)] = &[
        (
            "circuit_breaker",
            "reverse_proxy `circuit_breaker` (circuit breakers are not implemented)",
        ),
        (
            "dynamic_upstreams",
            "reverse_proxy `dynamic_upstreams` (dynamic upstream discovery is not implemented)",
        ),
        (
            "proxy_status_name",
            "reverse_proxy `proxy_status_name` (Proxy-Status headers are not implemented)",
        ),
        (
            "stream_timeout",
            "reverse_proxy `stream_timeout` (proxied stream timeouts are not implemented)",
        ),
        (
            "stream_buffer_size",
            "reverse_proxy `stream_buffer_size` (stream buffer sizing is not implemented)",
        ),
        (
            "stream_close_delay",
            "reverse_proxy `stream_close_delay` (stream close delays are not implemented)",
        ),
    ];
    for (field, feature) in UNSUPPORTED {
        if object.get(*field).is_some() {
            let _ = path;
            return Err(HttpError::NotImplemented {
                feature,
                tracking_id: "T-PROXY-037",
            });
        }
    }
    // `request_buffers`/`response_buffers` are accepted and inert while response streaming is
    // always on (DIV-0009); `verbose_logs` only affects logging, so ignoring it cannot change
    // request handling.
    Ok(())
}

/// Parse Caddy's `reverse_proxy.flush_interval` (`caddy.Duration`, integer nanoseconds in JSON).
///
/// Caddy's sentinel `-1` means "flush immediately after every write" and is the default. The
/// streaming implementation flushes each frame immediately, so an explicit positive interval is
/// accepted for compatibility but does not coalesce frames yet (DIV-0060).
fn parse_flush_interval(value: Option<&Value>, path: &str) -> HttpResult<FlushInterval> {
    let Some(value) = value else {
        return Ok(FlushInterval::Immediate);
    };
    let Some(nanos) = value.as_i64() else {
        return Err(invalid(
            path,
            "flush_interval must be an integer number of nanoseconds (Caddy JSON duration); -1 means immediate",
        ));
    };
    if nanos < 0 {
        return Ok(FlushInterval::Immediate);
    }
    Ok(FlushInterval::Interval(Duration::from_nanos(nanos as u64)))
}

#[async_trait]
impl Handler for ReverseProxyHandler {
    fn name(&self) -> &'static str {
        "reverse_proxy"
    }

    /// `T-PROXY-039` capability policy: a handler that can retry (`retries`/`try_duration`) or
    /// run `handle_response` routes needs the complete request body buffered before dispatch so it
    /// can be replayed. Otherwise the proxy streams the body exactly once.
    fn requires_buffered_request_body(&self) -> bool {
        // FastCGI cannot express a body of unknown length (`CONTENT_LENGTH` is required).
        self.transport.fastcgi.is_some()
            || self.retries > 0
            || !self.try_duration.is_zero()
            || self.handle_response.is_configured()
    }

    async fn handle(&self, request: Request) -> HttpResult<Outcome> {
        let mut request = request;
        let buffered_body = self.requires_buffered_request_body();
        if buffered_body {
            match request.collect_body(None).await {
                Ok(_) => {}
                Err(caddy_rs_http::body::BodyError::TooLarge { .. }) => {
                    return Ok(Outcome::Respond(Response::text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "413 Request Entity Too Large",
                    )))
                }
                Err(error) => {
                    return Ok(Outcome::Respond(Response::text(
                        StatusCode::BAD_GATEWAY,
                        format!("502 Bad Gateway: cannot read request body: {error}"),
                    )))
                }
            }
        }
        let mut stream_taken = false;
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
            let candidates: Vec<Arc<Upstream>> = self
                .upstreams
                .iter()
                .filter(|upstream| self.upstream_available(upstream, now))
                .cloned()
                .collect();
            let Some(upstream) = self.balancer.select(&candidates, &request) else {
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
            upstream.record_request();
            let body = match self.attempt_body(&mut request, buffered_body, &mut stream_taken) {
                Ok(body) => body,
                Err(message) => {
                    return Ok(Outcome::Respond(Response::text(
                        StatusCode::BAD_GATEWAY,
                        format!("502 Bad Gateway: {message}"),
                    )))
                }
            };
            match self.forward(&upstream, &request, body).await {
                Ok(forwarded) => {
                    // Caddy applies passive response checks before deciding on retry_match, so an
                    // unhealthy_status strike is recorded even when the response is retried.
                    if let Some(passive) = &self.passive {
                        let strikes = passive.record_response(
                            &upstream.dial,
                            forwarded.status,
                            forwarded.latency,
                            std::time::Instant::now(),
                        );
                        upstream.record_failures(strikes);
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
                    // Caddy evaluates `handle_response` after `retry_match`; a matching 2xx
                    // forward-auth response continues the handler chain (gate passed), while a
                    // non-matching 401/403 falls through to the normal response below.
                    if self.handle_response.is_configured() {
                        if let Some(result) = self.handle_response.evaluate(
                            &request,
                            response.status,
                            &response.headers,
                        ) {
                            return Ok(match result {
                                HandleResponseResult::Continue(request) => {
                                    Outcome::Continue(request)
                                }
                                HandleResponseResult::Respond(response) => {
                                    Outcome::Respond(response)
                                }
                            });
                        }
                    }
                    let status = response.status;
                    let upstream_headers = response.headers.clone();
                    self.apply_response_headers_to(
                        &mut response.headers,
                        &request,
                        status,
                        &upstream_headers,
                    );
                    return Ok(Outcome::Respond(response));
                }
                Err(error) if error.is_upgrade_not_supported() => {
                    // The upstream upgraded, but this path returns a complete buffered Response and
                    // cannot carry a raw tunnel. Fail loudly instead of returning a broken 101.
                    return Err(HttpError::UpgradeNotRepresentable {
                        context: "reverse_proxy buffered Handler::handle",
                    });
                }
                Err(error) => {
                    eprintln!(
                        "caddy-rs: reverse_proxy upstream `{}` failed: {error}",
                        upstream.dial
                    );
                    if let Some(status) = error.explicit_status() {
                        return Ok(Outcome::Respond(Response::text(
                            status,
                            format!("{status}"),
                        )));
                    }
                    upstream.record_failure();
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

    /// Streaming variant of [`Handler::handle`]: response headers are returned immediately and the
    /// upstream body is streamed frame by frame (no full-body buffering).
    ///
    /// Retry, load-balancing, passive health-check and response-header behaviour matches the
    /// buffered path; the only difference is that the body is not collected. A retried response
    /// drops its upstream body, cancelling the upstream transfer.
    async fn handle_streaming(&self, request: Request) -> HttpResult<StreamingOutcome> {
        let mut request = request;
        let buffered_body = self.requires_buffered_request_body();
        if buffered_body {
            match request.collect_body(None).await {
                Ok(_) => {}
                Err(caddy_rs_http::body::BodyError::TooLarge { .. }) => {
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        Response::text(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "413 Request Entity Too Large",
                        ),
                    )))
                }
                Err(error) => {
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        Response::text(
                            StatusCode::BAD_GATEWAY,
                            format!("502 Bad Gateway: cannot read request body: {error}"),
                        ),
                    )))
                }
            }
        }
        let mut stream_taken = false;
        let deadline = if self.try_duration.is_zero() {
            None
        } else {
            Some(tokio::time::Instant::now() + self.try_duration)
        };
        let mut attempts: u32 = 0;
        loop {
            let now = std::time::Instant::now();
            let candidates: Vec<Arc<Upstream>> = self
                .upstreams
                .iter()
                .filter(|upstream| self.upstream_available(upstream, now))
                .cloned()
                .collect();
            let Some(upstream) = self.balancer.select(&candidates, &request) else {
                if !self.retry_allowed(attempts, deadline) {
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        Response::text(StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable"),
                    )));
                }
                attempts += 1;
                self.wait_before_retry().await;
                continue;
            };
            let _guard = upstream.connection_started();
            upstream.record_request();
            let body = match self.attempt_body(&mut request, buffered_body, &mut stream_taken) {
                Ok(body) => body,
                Err(message) => {
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        Response::text(
                            StatusCode::BAD_GATEWAY,
                            format!("502 Bad Gateway: {message}"),
                        ),
                    )))
                }
            };
            match self.forward_streaming(&upstream, &request, body).await {
                Ok(Forwarded::Upgrade(forwarded)) => {
                    if let Some(passive) = &self.passive {
                        let strikes = passive.record_response(
                            &upstream.dial,
                            forwarded.status,
                            forwarded.latency,
                            std::time::Instant::now(),
                        );
                        upstream.record_failures(strikes);
                    }
                    // A configured retry match may still ask for another attempt; the tunnel is
                    // dropped (which closes the upstream) before retrying. Once the retry budget is
                    // spent the successful upgrade is served as-is.
                    let probe = Response {
                        status: forwarded.status,
                        headers: forwarded.headers.clone(),
                        body: Bytes::new(),
                    };
                    if self.retry_match.matches_response(&request, &probe)
                        && self.retry_allowed(attempts, deadline)
                    {
                        attempts += 1;
                        drop(forwarded);
                        self.wait_before_retry().await;
                        continue;
                    }
                    // `forward_auth`/`handle_response` rules match normal responses; a protocol
                    // switch is passed through untouched.
                    return Ok(StreamingOutcome::Upgrade(UpgradedResponse::new(
                        forwarded.status,
                        forwarded.headers,
                        forwarded.tunnel,
                    )));
                }
                Ok(Forwarded::Streaming(forwarded)) => {
                    if let Some(passive) = &self.passive {
                        let strikes = passive.record_response(
                            &upstream.dial,
                            forwarded.status,
                            forwarded.latency,
                            std::time::Instant::now(),
                        );
                        upstream.record_failures(strikes);
                    }
                    // `retry_match` only inspects the request and the response status, so a
                    // bodyless probe response is enough to evaluate it; the stream is untouched.
                    let probe = Response {
                        status: forwarded.status,
                        headers: forwarded.headers.clone(),
                        body: Bytes::new(),
                    };
                    if self.retry_match.matches_response(&request, &probe) {
                        if self.retry_allowed(attempts, deadline) {
                            attempts += 1;
                            // Drop the upstream body before retrying so the old upstream request
                            // is cancelled instead of leaked.
                            drop(forwarded);
                            self.wait_before_retry().await;
                            continue;
                        }
                        return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                            Response {
                                status: forwarded.status,
                                headers: HeaderMap::new(),
                                body: Bytes::new(),
                            },
                        )));
                    }
                    // A matching response handler either continues the chain with the auth headers
                    // copied onto the original request (2xx gate) or terminates with a synthetic
                    // response; otherwise the upstream response is streamed through unchanged.
                    if self.handle_response.is_configured() {
                        if let Some(result) = self.handle_response.evaluate(
                            &request,
                            forwarded.status,
                            &forwarded.headers,
                        ) {
                            return Ok(match result {
                                HandleResponseResult::Continue(request) => {
                                    // Cancel the auth response body: the chain continues and the
                                    // auth body is never sent to the client.
                                    drop(forwarded);
                                    StreamingOutcome::Continue(request)
                                }
                                HandleResponseResult::Respond(response) => {
                                    StreamingOutcome::Respond(StreamingResponse::from_buffered(
                                        response,
                                    ))
                                }
                            });
                        }
                    }
                    let mut response = StreamingResponse::new(
                        forwarded.status,
                        forwarded.headers,
                        Body::from_stream(forwarded.body),
                    );
                    let status = response.status;
                    let upstream_headers = response.headers.clone();
                    self.apply_response_headers_to(
                        &mut response.headers,
                        &request,
                        status,
                        &upstream_headers,
                    );
                    return Ok(StreamingOutcome::Respond(response));
                }
                Err(error) => {
                    eprintln!(
                        "caddy-rs: reverse_proxy upstream `{}` failed: {error}",
                        upstream.dial
                    );
                    if let Some(status) = error.explicit_status() {
                        return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                            Response::text(status, format!("{status}")),
                        )));
                    }
                    upstream.record_failure();
                    if let Some(passive) = &self.passive {
                        passive.record_failure(&upstream.dial, std::time::Instant::now());
                    }
                    let retryable =
                        error.is_dial_error() || self.retry_match.matches_transport_error(&request);
                    if !retryable || !self.retry_allowed(attempts, deadline) {
                        return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                            Response::text(StatusCode::BAD_GATEWAY, "502 Bad Gateway"),
                        )));
                    }
                    attempts += 1;
                    self.wait_before_retry().await;
                }
            }
        }
    }
}

/// Build the client-facing headers for a `101 Switching Protocols` response.
///
/// Hop-by-hop headers are stripped as for normal responses, then the upgrade negotiation pair is
/// restored canonically (`Upgrade: <protocol>` and `Connection: Upgrade`). Other hop-by-hop
/// headers (keep-alive, transfer-encoding, ...) stay stripped. Caddy likewise does not apply
/// `header.response` operations to 101 responses.
fn upgrade_response_headers(upstream_headers: &HeaderMap) -> HeaderMap {
    let upgrade = upstream_headers
        .get(http::header::UPGRADE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("upgrade"));
    let mut headers = strip_hop_by_hop(upstream_headers);
    headers.insert(http::header::UPGRADE, upgrade);
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("Upgrade"),
    );
    headers
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
/// Caddy's upstream request `Via` value: `<client HTTP major.minor> Caddy`.
///
/// caddy-rs' `Request` does not carry the client HTTP version; the server sets Caddy's
/// `{http.request.proto}` placeholder value (for example `HTTP/2.0`) in the `http.request.proto`
/// request variable when preparing requests (server-side follow-up for T-PROXY-024). Without it the
/// value falls back to `1.1`, matching the HTTP/1.1 baseline of the current server pipeline.
fn client_via_value(request: &Request) -> String {
    let raw = request
        .vars
        .get("http.request.proto")
        .map(String::as_str)
        .unwrap_or("1.1");
    let proto = raw.strip_prefix("HTTP/").unwrap_or(raw);
    format!("{proto} Caddy")
}

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

/// Parsed `reverse_proxy.headers`: request operations (applied before sending upstream) and
/// response operations (applied to the proxied response).
struct HeaderConfig {
    request: HeaderOps,
    response: HeaderOps,
}

/// Parse Caddy's embedded `headers` handler.
///
/// Only request/response `add`/`set`/`delete` are implemented. Caddy's `replace` operations
/// require a regex engine that is unavailable offline, and `deferred`/`require` change *when*
/// response operations apply; all are rejected loudly by [`HeaderOps::from_json`] (T-PROXY-037)
/// rather than silently misapplying security headers.
fn parse_headers(value: Option<&Value>, path: &str) -> HttpResult<HeaderConfig> {
    let Some(value) = value else {
        return Ok(HeaderConfig {
            request: HeaderOps::default(),
            response: HeaderOps::default(),
        });
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`headers` must be an object"))?;
    let request = object
        .get("request")
        .map(|request| HeaderOps::from_json(request, &format!("{path}.headers.request")))
        .transpose()?
        .unwrap_or_default();
    let response = object
        .get("response")
        .map(|response| HeaderOps::from_json(response, &format!("{path}.headers.response")))
        .transpose()?
        .unwrap_or_default();
    Ok(HeaderConfig { request, response })
}

/// Parse `transport` (Caddy `http` transport only) and build the TLS client configuration when
/// `transport.tls` is configured.
///
/// TLS is enabled by the mere presence of the `tls` object, even `{}` (Caddy semantics). Options
/// this build cannot honour fail loudly instead of silently changing transport behaviour.
/// Parsed `transport` section for Caddy's HTTP upstream transport.
#[derive(Debug, Clone, Default)]
struct TransportConfig {
    /// TLS client configuration when `transport.tls` is present.
    tls: Option<Arc<UpstreamTls>>,
    /// Cleartext HTTP/2 with prior knowledge (Caddy `versions` containing `h2c`, no TLS).
    h2c: bool,
    /// TLS ALPN offers HTTP/2 (Caddy `versions` containing `2` or `h2c`).
    alpn_h2: bool,
    /// FastCGI transport configuration when `protocol` is `"fastcgi"`.
    fastcgi: Option<Arc<FastCgiTransport>>,
}

/// TCP port of a `host:port` dial, if any (Unix-socket dials have no port).
fn dial_port(dial: &str) -> Option<u16> {
    if dial == "unix" || dial.starts_with("unix/") {
        return None;
    }
    let host_port = if dial.starts_with('[') {
        // `[v6]:port` — take the text after the closing bracket.
        dial.split_once(']')?.1.strip_prefix(':')?
    } else {
        dial.rsplit_once(':')?.1
    };
    host_port.parse().ok()
}

/// Build one client per upstream. The per-upstream connector dials its bound target regardless of
/// the request URI authority, which lets the proxy put the client's Host in the URI (HTTP/2
/// `:authority`) while still dialing the configured upstream.
fn build_upstream_clients(
    upstreams: &[Arc<Upstream>],
    transport: &TransportConfig,
    path: &str,
) -> HttpResult<Vec<UpstreamClient>> {
    upstreams
        .iter()
        .map(|upstream| {
            build_upstream_client(
                upstream,
                upstream_tls(upstream, transport),
                transport.h2c,
                false,
            )
            .map_err(|message| invalid(&format!("{path}.transport"), message))
        })
        .collect()
}

/// The TLS client configuration for one upstream (`None` when `tls.except_ports` excluded it).
fn upstream_tls(upstream: &Upstream, transport: &TransportConfig) -> Option<Arc<UpstreamTls>> {
    if upstream.tls {
        transport.tls.clone()
    } else {
        None
    }
}

/// HTTP/1.1-only companion clients used for protocol-upgrade requests when the transport prefers
/// HTTP/2 (upgrades cannot be carried over HTTP/2).
fn build_upgrade_clients(
    upstreams: &[Arc<Upstream>],
    transport: &TransportConfig,
    path: &str,
) -> HttpResult<Vec<UpstreamClient>> {
    upstreams
        .iter()
        .map(|upstream| {
            build_upstream_client(
                upstream,
                upstream_tls(upstream, transport),
                transport.h2c,
                true,
            )
            .map_err(|message| invalid(&format!("{path}.transport"), message))
        })
        .collect()
}

/// Parse `transport` (Caddy's `http` transport) into TLS and HTTP-version configuration.
///
/// HTTP version semantics (matching Caddy v2.11.7 / Go's `http.Transport`):
///
/// * `versions` defaults to Caddy's `["1.1", "2"]`.
/// * Allowed values are `1.1`, `2`, `h2c`, `3`; anything else is a located error and `3` is a
///   loud `NotImplemented` (HTTP/3 upstreams).
/// * TLS upstreams: HTTP/2 is offered via ALPN (`["h2","http/1.1"]`) when `2` or `h2c` is listed,
///   because Go's transport always keeps the HTTP/1.1 fallback. With neither listed, only
///   `http/1.1` is offered.
/// * Cleartext upstreams: `2` alone does not enable HTTP/2 (Go's plaintext transport stays
///   HTTP/1.1); `h2c` opts into HTTP/2 prior knowledge.
fn parse_transport(value: Option<&Value>, path: &str) -> HttpResult<TransportConfig> {
    let Some(value) = value else {
        return Ok(TransportConfig::default());
    };
    let transport_path = format!("{path}.transport");
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&transport_path, "`transport` must be an object"))?;

    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("http");
    if protocol == "fastcgi" {
        // Caddy's FastCGI transport has its own module shape; `from_json` rejects any HTTP
        // transport field (`tls`, `versions`, ...) instead of silently ignoring it.
        let fastcgi = FastCgiTransport::from_json(value, &transport_path)?;
        return Ok(TransportConfig {
            fastcgi: Some(Arc::new(fastcgi)),
            ..TransportConfig::default()
        });
    }
    if protocol != "http" {
        return Err(HttpError::NotImplemented {
            feature: "non-HTTP upstream transports other than FastCGI",
            tracking_id: "PROXY-TRANSPORT-PROTOCOL",
        });
    }

    // Caddy defaults `versions` to ["1.1", "2"] when unset.
    let versions: Vec<String> = match object.get("versions") {
        None | Some(Value::Null) => vec!["1.1".to_string(), "2".to_string()],
        Some(versions) => {
            let versions = versions.as_array().ok_or_else(|| {
                invalid(
                    &format!("{transport_path}.versions"),
                    "`versions` must be an array of strings",
                )
            })?;
            versions
                .iter()
                .map(|version| {
                    version.as_str().map(str::to_string).ok_or_else(|| {
                        invalid(
                            &format!("{transport_path}.versions"),
                            "`versions` entries must be strings",
                        )
                    })
                })
                .collect::<HttpResult<Vec<_>>>()?
        }
    };
    for version in &versions {
        match version.as_str() {
            "1.1" | "2" | "h2c" => {}
            "3" => {
                return Err(HttpError::NotImplemented {
                    feature: "HTTP/3 upstream transports",
                    tracking_id: "PROXY-H3-UPSTREAM",
                })
            }
            other => {
                return Err(invalid(
                    &format!("{transport_path}.versions"),
                    format!(
                        "unsupported HTTP version: {other}, supported versions: 1.1, 2, h2c, 3"
                    ),
                ))
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

    let tls_present = object.get("tls").is_some();
    let tls = match object.get("tls") {
        Some(tls) => {
            let alpn_h2 = versions
                .iter()
                .any(|version| version == "2" || version == "h2c");
            let alpn: &[&[u8]] = if alpn_h2 {
                &[b"h2", b"http/1.1"]
            } else {
                &[b"http/1.1"]
            };
            Some(Arc::new(UpstreamTls::from_json_with_alpn(
                tls,
                &format!("{transport_path}.tls"),
                alpn,
            )?))
        }
        None => None,
    };
    let alpn_h2 = tls_present
        && versions
            .iter()
            .any(|version| version == "2" || version == "h2c");
    let h2c = !tls_present && versions.iter().any(|version| version == "h2c");
    Ok(TransportConfig {
        tls,
        h2c,
        alpn_h2,
        fastcgi: None,
    })
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

/// Build the `reverse_proxy` handler factory and track every handler it builds in `sink`.
///
/// The server runtime uses this to expose live `/reverse_proxy/upstreams` counters for the active
/// configuration generation: each apply builds a fresh sink, and the sink only becomes the admin
/// source once that generation is serving.
pub fn handler_factory_with_status_sink(sink: Arc<UpstreamStatusSink>) -> CustomHandlerFactory {
    Arc::new(move |value: &Value, path: &str| {
        let name = value.get("handler").and_then(Value::as_str);
        if name == Some("reverse_proxy") {
            let handler = Arc::new(ReverseProxyHandler::from_json(value, path)?);
            sink.register(&handler);
            let shared: SharedHandler = handler;
            Ok(Some(shared))
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
    async fn upstream_counters_track_successful_attempts() {
        let dial = spawn_echo_upstream().await;
        let handler = handler(&dial);
        let Outcome::Respond(response) =
            handler.handle(get_request("/counted", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            handler.upstream_statuses(),
            vec![UpstreamStatus {
                address: dial.clone(),
                num_requests: 1,
                fails: 0,
            }]
        );
    }

    #[tokio::test]
    async fn upstream_counters_count_each_retry_attempt_and_failure() {
        // Reserve then release a loopback port so the dial is refused: retries = 1 means two
        // attempts against the same (dead) upstream, and both are failures.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "load_balancing": {"retries": 1}
        }));
        let Outcome::Respond(response) = handler.handle(get_request("/dead", None)).await.unwrap()
        else {
            panic!("expected 502 response");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            handler.upstream_statuses(),
            vec![UpstreamStatus {
                address: dial,
                num_requests: 2,
                fails: 2,
            }]
        );
    }

    #[tokio::test]
    async fn upstream_counters_track_streaming_requests() {
        let dial = spawn_echo_upstream().await;
        let handler = handler(&dial);
        let outcome = handler
            .handle_streaming(get_request("/streamed", None))
            .await
            .unwrap();
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            handler.upstream_statuses(),
            vec![UpstreamStatus {
                address: dial,
                num_requests: 1,
                fails: 0,
            }]
        );
    }

    #[tokio::test]
    async fn upstream_status_sink_tracks_built_handlers_and_drops_retired_ones() {
        let dial = spawn_echo_upstream().await;
        let sink = UpstreamStatusSink::new();
        let factory = handler_factory_with_status_sink(Arc::clone(&sink));
        let config = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}]
        });
        let first = factory(&config, "handler").unwrap().unwrap();
        let second = factory(&config, "handler").unwrap().unwrap();
        let Outcome::Respond(response) = first.handle(get_request("/one", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        let Outcome::Respond(response) = second.handle(get_request("/two", None)).await.unwrap()
        else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            sink.snapshot(),
            vec![UpstreamStatus {
                address: dial,
                num_requests: 2,
                fails: 0,
            }],
            "handlers sharing an address are merged like Caddy's global host pool"
        );
        drop(first);
        drop(second);
        assert!(
            sink.snapshot().is_empty(),
            "retired handlers must disappear from the sink"
        );
    }

    /// Upstream that reports the outbound `Via`, `X-Forwarded-For` and `X-Forwarded-Host` values.
    async fn spawn_forwarded_probe_upstream() -> String {
        spawn_upstream(
            move |request: hyper::Request<hyper::body::Incoming>| async move {
                let header = |name: &str| {
                    request
                        .headers()
                        .get_all(name)
                        .iter()
                        .filter_map(|value| value.to_str().ok())
                        .collect::<Vec<_>>()
                        .join("|")
                };
                let body = format!(
                    "via={}\nxff={}\nxfh={}",
                    header("via"),
                    header("x-forwarded-for"),
                    header("x-forwarded-host"),
                );
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from(body)))
                        .expect("response"),
                )
            },
        )
        .await
    }

    #[test]
    fn load_balancing_policy_modules_are_parsed() {
        for policy in [
            serde_json::json!({"policy": "random"}),
            serde_json::json!({"policy": "first"}),
            serde_json::json!({"policy": "round_robin"}),
            serde_json::json!({"policy": "least_conn"}),
            serde_json::json!({"policy": "ip_hash"}),
            serde_json::json!({"policy": "client_ip_hash"}),
            serde_json::json!({"policy": "uri_hash"}),
            serde_json::json!({"policy": "header", "field": "X-Session"}),
            serde_json::json!({"policy": "query", "key": "user"}),
            serde_json::json!({"policy": "weighted_round_robin", "weights": [1, 1]}),
        ] {
            build_handler(serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}, {"dial": "localhost:9001"}],
                "load_balancing": {"selection_policy": policy}
            }));
        }
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}],
                "load_balancing": {"selection_policy": {"policy": "cookie", "name": "lb"}}
            }),
            "handler",
        )
        .err()
        .expect("cookie policy must be rejected loudly");
        assert!(error.to_string().contains("T-PROXY-013-COOKIE"), "{error}");

        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}],
                "load_balancing": {"selection_policy": {"policy": "magic"}}
            }),
            "handler",
        )
        .err()
        .expect("unknown policy must be rejected");
        assert!(error.to_string().contains("magic"), "{error}");
    }

    #[tokio::test]
    async fn upstream_request_gets_via_with_the_client_protocol() {
        let dial = spawn_forwarded_probe_upstream().await;
        let handler = handler(&dial);
        let mut request = get_request("/via", Some("203.0.113.7:5555"));
        request
            .vars
            .insert("http.request.proto".to_string(), "HTTP/2.0".to_string());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("via=2.0 Caddy"), "{body}");

        // Without the proto variable (current server pipeline) the HTTP/1.1 baseline is used.
        let Outcome::Respond(response) = handler
            .handle(get_request("/via-default", Some("203.0.113.7:5555")))
            .await
            .unwrap()
        else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("via=1.1 Caddy"), "{body}");

        // A client-supplied Via is preserved and Caddy's value is appended.
        let mut request = get_request("/via-client", Some("203.0.113.7:5555"));
        request
            .headers
            .insert(http::header::VIA, "1.0 edge".parse().unwrap());
        request
            .vars
            .insert("http.request.proto".to_string(), "1.1".to_string());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("1.0 edge"), "{body}");
        assert!(body.contains("1.1 Caddy"), "{body}");
    }

    #[tokio::test]
    async fn server_trusted_proxy_var_makes_forwarded_headers_trusted() {
        let dial = spawn_forwarded_probe_upstream().await;
        let handler = handler(&dial);

        // Untrusted peer (no server/handler trusted_proxies): prior forwarded headers are dropped.
        let mut request = get_request("/untrusted", Some("198.51.100.9:5555"));
        request
            .headers
            .insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-host", "prior.example".parse().unwrap());
        request
            .vars
            .insert("trusted_proxy".to_string(), "false".to_string());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(body.contains("xff=198.51.100.9"), "{body}");
        assert!(body.contains("xfh=example.com"), "{body}");

        // Server-level trusted_proxies (simulated through Caddy's request variable) trusts prior
        // forwarded values and appends the peer address.
        let mut request = get_request("/trusted", Some("198.51.100.9:5555"));
        request
            .headers
            .insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-host", "prior.example".parse().unwrap());
        request
            .vars
            .insert("trusted_proxy".to_string(), "true".to_string());
        request
            .vars
            .insert("client_ip".to_string(), "203.0.113.5".to_string());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_text(&response);
        assert!(
            body.contains("xff=203.0.113.5, 198.51.100.9"),
            "trusted server peer must keep prior X-Forwarded-For: {body}"
        );
        assert!(body.contains("xfh=prior.example"), "{body}");
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
    fn accepts_h2_and_h2c_transport_versions() {
        // Caddy's H2C transport output: cleartext HTTP/2 prior knowledge.
        build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "transport": {"protocol": "http", "versions": ["h2c", "2"]}
        }));
        // TLS upstream with HTTP/2 via ALPN.
        build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8443"}],
            "transport": {
                "protocol": "http",
                "versions": ["2"],
                "tls": {"insecure_skip_verify": true}
            }
        }));
        // Default versions (absent) match Caddy's ["1.1","2"].
        build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8443"}],
            "transport": {"protocol": "http", "tls": {"insecure_skip_verify": true}}
        }));
    }

    #[test]
    fn rejects_unsupported_http_versions() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "transport": {"protocol": "http", "versions": ["1.0"]}
            }),
            "handler",
        )
        .err()
        .expect("unknown HTTP version must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("unsupported HTTP version: 1.0"),
            "{message}"
        );
        assert!(
            message.contains("supported versions: 1.1, 2, h2c, 3"),
            "{message}"
        );

        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "transport": {"protocol": "http", "versions": ["3"]}
            }),
            "handler",
        )
        .err()
        .expect("HTTP/3 upstream transport must fail loudly");
        assert!(error.to_string().contains("PROXY-H3-UPSTREAM"), "{error}");

        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "transport": {"protocol": "http", "versions": [2]}
            }),
            "handler",
        )
        .err()
        .expect("non-string versions must be rejected");
        assert!(error.to_string().contains("must be strings"), "{error}");
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
        // HTTP/2 versions are accepted; ALPN h2 negotiation is covered by the h2 tests.
        ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8443"}],
                "transport": {"protocol": "http", "versions": ["2"], "tls": {}}
            }),
            "handler",
        )
        .unwrap();
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

    // ---- streaming response path -----------------------------------------------------

    use caddy_rs_http::body::BodyError as HttpBodyError;
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// Upstream serving a channel-fed streaming body, so tests control chunk timing and failures.
    async fn spawn_channel_upstream(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
    ) -> (
        String,
        mpsc::Sender<std::result::Result<Bytes, HttpBodyError>>,
    ) {
        let (sender, receiver) = mpsc::channel(8);
        let receiver = Arc::new(std::sync::Mutex::new(Some(receiver)));
        let address = spawn_body_upstream(move |_request| {
            let receiver = Arc::clone(&receiver);
            async move {
                let receiver = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .expect("one streaming request per test upstream");
                let mut builder = hyper::Response::builder().status(status);
                for (name, value) in headers {
                    builder = builder.header(*name, *value);
                }
                Ok(builder
                    .body(StreamingBody::from_chunks(receiver))
                    .expect("streaming response"))
            }
        })
        .await;
        (address, sender)
    }

    async fn spawn_body_upstream<F, Fut>(serve: F) -> String
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<hyper::Response<StreamingBody>, Infallible>>
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

    fn streaming_body(outcome: StreamingOutcome) -> StreamingBody {
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a proxied response");
        };
        match response.body {
            Body::Stream(stream) => stream,
            Body::Bytes(_) => panic!("expected a streaming body"),
        }
    }

    #[tokio::test]
    async fn streams_first_byte_before_upstream_finishes() {
        let (dial, sender) =
            spawn_channel_upstream(200, &[("content-type", "text/event-stream")]).await;
        let handler = handler(&dial);
        let started = std::time::Instant::now();
        let outcome = handler
            .handle_streaming(get_request("/events", None))
            .await
            .unwrap();
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a proxied response");
        };
        assert_eq!(response.status, 200);
        assert!(response.is_streaming(), "response body must stream");
        // Headers arrive before any upstream body byte.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "response headers must not wait for the upstream body"
        );
        let mut body = match response.body {
            Body::Stream(stream) => stream,
            Body::Bytes(_) => panic!("expected a streaming body"),
        };

        sender
            .send(Ok(Bytes::from_static(b"data: first\n\n")))
            .await
            .expect("send first chunk");
        let first = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("first frame timeout")
            .expect("first frame")
            .expect("data");
        assert_eq!(
            first.into_data().unwrap(),
            Bytes::from_static(b"data: first\n\n")
        );
        // The upstream body is still open: the downstream already saw bytes, so the proxy did not
        // buffer the full response.
        assert!(!sender.is_closed());

        sender
            .send(Ok(Bytes::from_static(b"data: second\n\n")))
            .await
            .expect("send second chunk");
        let second = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("second frame timeout")
            .expect("second frame")
            .expect("data");
        assert_eq!(
            second.into_data().unwrap(),
            Bytes::from_static(b"data: second\n\n")
        );

        drop(sender);
        assert!(tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("end timeout")
            .is_none());
    }

    #[tokio::test]
    async fn preserves_status_headers_and_content_length() {
        let (dial, sender) = spawn_channel_upstream(
            201,
            &[
                ("content-type", "application/octet-stream"),
                ("content-length", "10"),
                ("x-upstream", "yes"),
                ("connection", "x-hop"),
                ("x-hop", "drop-me"),
            ],
        )
        .await;
        let handler = handler(&dial);
        let StreamingOutcome::Respond(response) = handler
            .handle_streaming(get_request("/blob", None))
            .await
            .unwrap()
        else {
            panic!("expected a proxied response");
        };
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers["content-type"], "application/octet-stream");
        assert_eq!(response.headers["content-length"], "10");
        assert_eq!(response.headers["x-upstream"], "yes");
        // Caddy adds Via and strips hop-by-hop headers on the streaming path too.
        assert!(response.headers.contains_key(http::header::VIA));
        assert!(response.headers.get("x-hop").is_none());

        let mut body = match response.body {
            Body::Stream(stream) => stream,
            Body::Bytes(_) => panic!("expected a streaming body"),
        };
        sender.send(Ok(Bytes::from_static(b"01234"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"56789"))).await.unwrap();
        drop(sender);
        let mut received = Vec::new();
        while let Some(frame) = body.frame().await {
            received.extend_from_slice(frame.unwrap().into_data().unwrap().as_ref());
        }
        assert_eq!(received, b"0123456789");
    }

    #[tokio::test]
    async fn mid_stream_error_after_headers_is_surfaced() {
        let (dial, sender) = spawn_channel_upstream(200, &[]).await;
        let handler = handler(&dial);
        let outcome = handler
            .handle_streaming(get_request("/broken", None))
            .await
            .unwrap();
        let mut body = streaming_body(outcome);

        sender
            .send(Ok(Bytes::from_static(b"partial")))
            .await
            .unwrap();
        let first = body.frame().await.expect("first frame").expect("data");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"partial"));

        sender
            .send(Err(HttpBodyError::upstream(std::io::Error::other(
                "upstream died mid-stream",
            ))))
            .await
            .unwrap();
        let error = body
            .frame()
            .await
            .expect("error frame")
            .expect_err("mid-stream error must surface after headers");
        // hyper surfaces a mid-body upstream failure as a connection read error; the exact
        // upstream message is not retransmitted by HTTP/1.1, but the error must be a body error.
        assert!(
            matches!(error, HttpBodyError::Upstream(_)),
            "expected an upstream body error, got: {error}"
        );
    }

    #[tokio::test]
    async fn dropping_the_response_body_cancels_the_upstream() {
        let (dial, sender) = spawn_channel_upstream(200, &[]).await;
        let handler = handler(&dial);
        let outcome = handler
            .handle_streaming(get_request("/cancel", None))
            .await
            .unwrap();
        let mut body = streaming_body(outcome);
        sender.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
        let first = body.frame().await.expect("first frame").expect("data");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"first"));

        // A client disconnect is modelled by dropping the response body; the upstream transfer
        // (and its channel receiver) must be cancelled instead of draining to completion. The
        // upstream learns about the disconnect on its next write, so keep feeding chunks until the
        // channel reports that the consumer is gone.
        drop(body);
        let cancelled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if sender.send(Ok(Bytes::from_static(b"x"))).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            cancelled.is_ok(),
            "upstream body was still alive after the downstream body was dropped"
        );
    }

    #[tokio::test]
    async fn buffered_handle_still_buffers_a_streaming_upstream() {
        let (dial, sender) = spawn_channel_upstream(200, &[]).await;
        let handler = handler(&dial);
        let producer = tokio::spawn(async move {
            sender.send(Ok(Bytes::from_static(b"full"))).await.unwrap();
            sender.send(Ok(Bytes::from_static(b"body"))).await.unwrap();
        });
        let Outcome::Respond(response) = handler
            .handle(get_request("/buffered", None))
            .await
            .unwrap()
        else {
            panic!("expected a proxied response");
        };
        producer.await.unwrap();
        assert_eq!(response.body, Bytes::from_static(b"fullbody"));
        assert_eq!(response.status, 200);
    }

    #[test]
    fn flush_interval_is_parsed_like_caddy() {
        let base = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:1"}]
        });
        let implicit = build_handler(base.clone());
        assert_eq!(implicit.flush_interval(), FlushInterval::Immediate);

        let mut negative = base.clone();
        negative["flush_interval"] = serde_json::json!(-1);
        assert_eq!(
            build_handler(negative).flush_interval(),
            FlushInterval::Immediate
        );

        let mut interval = base.clone();
        interval["flush_interval"] = serde_json::json!(100_000_000_i64);
        assert_eq!(
            build_handler(interval).flush_interval(),
            FlushInterval::Interval(Duration::from_millis(100))
        );

        let mut invalid = base;
        invalid["flush_interval"] = serde_json::json!("soon");
        let error = match ReverseProxyHandler::from_json(&invalid, "handler") {
            Ok(_) => panic!("string flush_interval must fail loudly"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("flush_interval"),
            "error must locate flush_interval: {error}"
        );
    }

    #[tokio::test]
    async fn router_streaming_path_proxies_without_buffering() {
        let (dial, sender) = spawn_channel_upstream(200, &[]).await;
        let routes = serde_json::json!([{
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}]
        }]);
        let router = caddy_rs_http::RouterBuilder::new()
            .with_custom_handler(handler_factory())
            .build(routes.as_array().unwrap())
            .expect("router builds");
        let response = router
            .handle_streaming(get_request("/routed", None))
            .await
            .expect("router streams");
        assert!(
            response.is_streaming(),
            "proxy body must reach the router as a stream"
        );
        let Body::Stream(mut body) = response.body else {
            panic!("expected a streaming body");
        };

        sender
            .send(Ok(Bytes::from_static(b"routed-first")))
            .await
            .expect("send first");
        let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("first frame timeout")
            .expect("first frame")
            .expect("data");
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from_static(b"routed-first")
        );
        assert!(!sender.is_closed(), "router must not buffer the proxy body");
    }

    #[tokio::test]
    async fn router_buffered_path_collects_proxy_streams() {
        let (dial, sender) = spawn_channel_upstream(200, &[]).await;
        let routes = serde_json::json!([{
            "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}]
        }]);
        let router = caddy_rs_http::RouterBuilder::new()
            .with_custom_handler(handler_factory())
            .build(routes.as_array().unwrap())
            .expect("router builds");
        let producer = tokio::spawn(async move {
            sender
                .send(Ok(Bytes::from_static(b"buffered")))
                .await
                .unwrap();
            sender.send(Ok(Bytes::from_static(b"-body"))).await.unwrap();
        });
        let response = router
            .handle(get_request("/routed", None))
            .await
            .expect("router buffers");
        producer.await.unwrap();
        assert_eq!(response.body, Bytes::from_static(b"buffered-body"));
    }

    // ---- Canonical `forward_auth` execution (T-PROXY-037) ---------------------------------

    #[derive(Debug, Clone, Default)]
    struct RecordedRequest {
        method: String,
        uri: String,
        headers: http::HeaderMap,
        body: bytes::Bytes,
    }

    fn canonical_forward_auth_handler(auth_dial: &str, copy_headers: &[&str]) -> Value {
        let mut routes = vec![serde_json::json!({"handle": [{"handler": "vars"}]})];
        for header in copy_headers {
            let placeholder = format!("{{http.reverse_proxy.header.{header}}}");
            routes.push(serde_json::json!({
                "handle": [{"handler": "headers", "request": {"delete": [header]}}]
            }));
            let mut set = serde_json::Map::new();
            set.insert(header.to_string(), serde_json::json!([placeholder]));
            let mut vars = serde_json::Map::new();
            vars.insert(placeholder.clone(), serde_json::json!([""]));
            routes.push(serde_json::json!({
                "handle": [{"handler": "headers", "request": {"set": Value::Object(set)}}],
                "match": [{"not": [{"vars": Value::Object(vars)}]}]
            }));
        }
        serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": auth_dial}],
            "rewrite": {"method": "GET", "uri": "/api/authz/forward-auth"},
            "headers": {"request": {"set": {
                "X-Forwarded-Method": ["{http.request.method}"],
                "X-Forwarded-Uri": ["{http.request.uri}"]
            }}},
            "handle_response": [{"match": {"status_code": [2]}, "routes": routes}]
        })
    }

    /// Spawn an upstream that records requests and answers with a fixed status/body/headers.
    async fn spawn_recording_upstream(
        status: u16,
        response_body: &'static str,
        response_headers: Vec<(&'static str, &'static str)>,
        recorded: Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
    ) -> String {
        spawn_upstream(move |request: hyper::Request<hyper::body::Incoming>| {
            let recorded = Arc::clone(&recorded);
            let response_headers = response_headers.clone();
            async move {
                let (parts, body_incoming) = request.into_parts();
                let request_body = body_incoming
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();
                recorded.lock().unwrap().push(RecordedRequest {
                    method: parts.method.to_string(),
                    uri: parts
                        .uri
                        .path_and_query()
                        .map(|value| value.as_str().to_string())
                        .unwrap_or_default(),
                    headers: parts.headers,
                    body: request_body,
                });
                let mut builder = hyper::Response::builder().status(status);
                for (name, value) in &response_headers {
                    builder = builder.header(*name, *value);
                }
                Ok::<_, Infallible>(
                    builder
                        .body(Full::new(Bytes::from_static(response_body.as_bytes())))
                        .expect("response"),
                )
            }
        })
        .await
    }

    /// Upstream that echoes the request method, URI, body and selected headers.
    async fn spawn_header_echo_upstream() -> String {
        spawn_upstream(
            move |request: hyper::Request<hyper::body::Incoming>| async move {
                let (parts, body_incoming) = request.into_parts();
                let body = body_incoming
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();
                let header = |name: &str| {
                    parts
                        .headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing")
                        .to_string()
                };
                let text = format!(
                    "method={}\nuri={}\nbody={}\nremote-user={}\nremote-email={}\nx-forwarded-method={}\nx-forwarded-uri={}\nauthorization={}",
                    parts.method,
                    parts
                        .uri
                        .path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/"),
                    String::from_utf8_lossy(&body),
                    header("remote-user"),
                    header("remote-email"),
                    header("x-forwarded-method"),
                    header("x-forwarded-uri"),
                    header("authorization"),
                );
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from(text)))
                        .expect("response"),
                )
            },
        )
        .await
    }

    fn build_chain_router(handlers: Vec<Value>) -> caddy_rs_http::Router {
        let routes = vec![serde_json::json!({"handle": handlers})];
        caddy_rs_http::RouterBuilder::new()
            .with_custom_handler(handler_factory())
            .build(&routes)
            .expect("router builds")
    }

    fn post_request(uri: &str, body: &'static str) -> Request {
        let mut request = Request::new(Method::POST, uri.parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request.body = Bytes::from_static(body.as_bytes());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn forward_auth_2xx_gate_passes_and_copies_headers() {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth = spawn_recording_upstream(
            200,
            "",
            vec![
                ("Remote-User", "alice"),
                ("Remote-Email", "alice@example.com"),
            ],
            Arc::clone(&recorded),
        )
        .await;
        let backend = spawn_header_echo_upstream().await;
        let router = build_chain_router(vec![
            canonical_forward_auth_handler(&auth, &["Remote-User", "Remote-Email"]),
            serde_json::json!({"handler": "reverse_proxy", "upstreams": [{"dial": backend}]}),
        ]);
        let mut request = post_request("/protected?x=1", "hello");
        request
            .headers
            .insert("remote-user", "attacker".parse().unwrap());

        let response = router.handle(request).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        let body = body_text(&response);
        // The backend sees the ORIGINAL request, now authorized by the auth service...
        assert!(body.contains("method=POST"), "{body}");
        assert!(body.contains("uri=/protected?x=1"), "{body}");
        assert!(body.contains("body=hello"), "{body}");
        // ...with auth-provided headers replacing any client-supplied value.
        assert!(body.contains("remote-user=alice"), "{body}");
        assert!(body.contains("remote-email=alice@example.com"), "{body}");
        // The forwarded-auth headers went to the auth service only.
        assert!(body.contains("x-forwarded-method=missing"), "{body}");

        // The auth sub-request was rewritten and carried the original method/URI.
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1, "exactly one auth sub-request");
        let auth_request = &recorded[0];
        assert_eq!(auth_request.method, "GET");
        assert_eq!(auth_request.uri, "/api/authz/forward-auth?x=1");
        assert_eq!(auth_request.headers["x-forwarded-method"], "POST");
        assert_eq!(auth_request.headers["x-forwarded-uri"], "/protected?x=1");
        assert!(
            auth_request.body.is_empty(),
            "rewritten GET drops the request body"
        );
        assert_eq!(auth_request.headers[http::header::HOST], "example.com");
    }

    #[tokio::test]
    async fn forward_auth_2xx_omitting_header_removes_client_supplied_value() {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth = spawn_recording_upstream(200, "", Vec::new(), Arc::clone(&recorded)).await;
        let backend = spawn_header_echo_upstream().await;
        let router = build_chain_router(vec![
            canonical_forward_auth_handler(&auth, &["Remote-User"]),
            serde_json::json!({"handler": "reverse_proxy", "upstreams": [{"dial": backend}]}),
        ]);
        let mut request = post_request("/protected", "");
        request
            .headers
            .insert("remote-user", "attacker".parse().unwrap());

        let response = router.handle(request).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        let body = body_text(&response);
        assert!(
            body.contains("remote-user=missing"),
            "client-injected authorization headers must be deleted when the auth service omits them: {body}"
        );
    }

    #[tokio::test]
    async fn forward_auth_401_and_403_pass_through_without_hitting_backend() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
            let auth = spawn_recording_upstream(
                status.as_u16(),
                "denied",
                vec![("WWW-Authenticate", "Basic")],
                Arc::clone(&recorded),
            )
            .await;
            let backend_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counters = Arc::clone(&backend_hits);
            let backend = spawn_upstream(move |_request| {
                let counters = Arc::clone(&counters);
                async move {
                    counters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::new()))
                            .expect("response"),
                    )
                }
            })
            .await;
            let router = build_chain_router(vec![
                canonical_forward_auth_handler(&auth, &["Remote-User"]),
                serde_json::json!({"handler": "reverse_proxy", "upstreams": [{"dial": backend}]}),
            ]);
            let response = router.handle(post_request("/protected", "")).await.unwrap();
            assert_eq!(
                response.status, status,
                "auth challenge must be passed through as {status}"
            );
            assert_eq!(body_text(&response), "denied");
            assert_eq!(response.headers["www-authenticate"], "Basic");
            assert_eq!(
                backend_hits.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "a failed auth check must not reach the backend"
            );
        }
    }

    #[tokio::test]
    async fn forward_auth_streaming_path_continues_on_2xx() {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth = spawn_recording_upstream(
            200,
            "",
            vec![("Remote-User", "alice")],
            Arc::clone(&recorded),
        )
        .await;
        let backend = spawn_header_echo_upstream().await;
        let router = build_chain_router(vec![
            canonical_forward_auth_handler(&auth, &["Remote-User"]),
            serde_json::json!({"handler": "reverse_proxy", "upstreams": [{"dial": backend}]}),
        ]);
        let streamed = router
            .handle_streaming(post_request("/protected", "hello"))
            .await
            .unwrap();
        let response = streamed.into_buffered().await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        let body = body_text(&response);
        assert!(body.contains("remote-user=alice"), "{body}");
        assert!(body.contains("uri=/protected"), "{body}");
    }

    #[tokio::test]
    async fn forward_auth_streaming_401_terminates_chain() {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth = spawn_recording_upstream(
            401,
            "denied",
            vec![("WWW-Authenticate", "Basic")],
            Arc::clone(&recorded),
        )
        .await;
        let handler = build_handler(canonical_forward_auth_handler(&auth, &["Remote-User"]));
        let outcome = handler
            .handle_streaming(post_request("/protected", ""))
            .await
            .unwrap();
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("401 must terminate the handler chain, not continue it");
        };
        let response = response.into_buffered().await.unwrap();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(&response), "denied");
    }

    #[tokio::test]
    async fn top_level_request_header_delete_is_applied() {
        let upstream = spawn_header_echo_upstream().await;
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "headers": {"request": {"delete": ["Authorization"]}}
        }));
        let mut request = post_request("/", "");
        request.headers.insert(
            http::header::AUTHORIZATION,
            "Bearer client".parse().unwrap(),
        );
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert!(
            body_text(&response).contains("authorization=missing"),
            "headers.request.delete must strip the header before proxying"
        );
    }

    #[test]
    fn rejects_unsupported_security_relevant_handler_fields() {
        for (field, value) in [
            ("circuit_breaker", serde_json::json!({"type": "x"})),
            ("dynamic_upstreams", serde_json::json!({"source": "x"})),
            ("proxy_status_name", serde_json::json!("caddy")),
            ("stream_timeout", serde_json::json!(1000)),
            ("stream_buffer_size", serde_json::json!(1024)),
            ("stream_close_delay", serde_json::json!(10)),
        ] {
            let mut config = serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}]
            });
            config[field] = value;
            let error = ReverseProxyHandler::from_json(&config, "handler")
                .err()
                .expect("unsupported handler field must be rejected");
            let message = error.to_string();
            assert!(
                message.contains(field),
                "error must name `{field}`: {message}"
            );
            assert!(message.contains("T-PROXY-037"), "{message}");
        }
    }

    #[test]
    fn rejects_unsupported_header_and_rewrite_and_handle_response_forms() {
        let unsupported_header_ops = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "headers": {"request": {"replace": {"X": [{"search": "a", "replace": "b"}]}}}
        });
        let error = ReverseProxyHandler::from_json(&unsupported_header_ops, "handler")
            .err()
            .expect("header replace must be rejected");
        assert!(error.to_string().contains("T-PROXY-037"), "{error}");

        let unsupported_rewrite = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "rewrite": {"strip_path_prefix": "/api"}
        });
        let error = ReverseProxyHandler::from_json(&unsupported_rewrite, "handler")
            .err()
            .expect("unsupported rewrite must be rejected");
        assert!(error.to_string().contains("T-PROXY-037"), "{error}");

        let unsupported_handle_response = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "handle_response": [{"routes": [{"handle": [{"handler": "file_server"}]}]}]
        });
        let error = ReverseProxyHandler::from_json(&unsupported_handle_response, "handler")
            .err()
            .expect("unsupported handle_response must be rejected");
        assert!(error.to_string().contains("T-PROXY-037"), "{error}");
    }

    #[test]
    fn accepts_upstream_max_requests_and_unknown_harmless_fields() {
        let handler = build_handler(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080", "max_requests": 7}],
            "some_field_caddy_also_ignores": true
        }));
        assert_eq!(handler.upstreams()[0].max_requests(), Some(7));
        assert!(!handler.upstreams()[0].is_full());
    }
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;
    use caddy_rs_http::{Tunnel, UpgradedResponse};
    use http::Method;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn handler(dial: &str) -> ReverseProxyHandler {
        ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "headers": {
                    "request": {"set": {"X-Added": ["yes"]}},
                    "response": {"set": {"X-Proxy": ["caddy-rs"]}}
                }
            }),
            "handler",
        )
        .expect("handler builds")
    }

    /// Read an HTTP/1 request head (through the blank line) from a raw upstream connection.
    async fn read_http_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) => head.push(byte[0]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    }

    /// A raw WebSocket-style upstream:
    /// * normal requests get `200 plain`;
    /// * upgrade requests get `101` and then raw bytes are echoed back (after an initial greeting).
    async fn spawn_upgrade_echo_upstream() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let head = read_http_head(&mut stream).await;
                    if header_value(&head, "upgrade").is_none() {
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
                                        Connection: close\r\n\r\nplain";
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                    let upgrade = header_value(&head, "upgrade").unwrap_or("missing");
                    let connection = header_value(&head, "connection").unwrap_or("missing");
                    let added = header_value(&head, "x-added").unwrap_or("missing");
                    let response = format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Connection: Upgrade\r\n\
                         Upgrade: {upgrade}\r\n\
                         Sec-WebSocket-Accept: test-accept\r\n\
                         X-Seen-Connection: {connection}\r\n\
                         X-Seen-Upgrade: {upgrade}\r\n\
                         X-Seen-X-Added: {added}\r\n\
                         Keep-Alive: timeout=5\r\n\
                         Transfer-Encoding: chunked\r\n\
                         \r\n"
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(b"greeting").await.is_err() {
                        return;
                    }
                    let mut buffer = [0_u8; 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => {
                                if stream.write_all(&buffer[..read]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        address.to_string()
    }

    fn upgrade_request(path: &str) -> Request {
        let mut request = Request::new(Method::GET, path.parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request.headers.insert(
            http::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        request
            .headers
            .insert(http::header::UPGRADE, "websocket".parse().unwrap());
        request.headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        request
            .headers
            .insert("sec-websocket-version", "13".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn upgrade_is_returned_as_a_tunnel_with_preserved_handshake_headers() {
        let dial = spawn_upgrade_echo_upstream().await;
        let handler = handler(&dial);
        let outcome = handler
            .handle_streaming(upgrade_request("/ws"))
            .await
            .expect("upgrade handshake");
        let StreamingOutcome::Upgrade(UpgradedResponse {
            status,
            headers,
            tunnel,
        }) = outcome
        else {
            panic!("expected an upgraded outcome");
        };
        assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(headers[http::header::UPGRADE], "websocket");
        assert_eq!(headers[http::header::CONNECTION], "Upgrade");
        assert_eq!(headers["sec-websocket-accept"], "test-accept");
        // The proxy reconstructed the upgrade negotiation for the upstream.
        assert_eq!(headers["x-seen-connection"], "Upgrade");
        assert_eq!(headers["x-seen-upgrade"], "websocket");
        // `header_up` operations still apply to upgrade requests.
        assert_eq!(headers["x-seen-x-added"], "yes");
        // Hop-by-hop response headers are stripped.
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());

        let mut tunnel = tunnel;
        let mut buffer = [0_u8; 8];
        tunnel
            .as_pinned_mut()
            .read_exact(&mut buffer)
            .await
            .expect("upstream greeting");
        assert_eq!(&buffer, b"greeting");
        tunnel
            .as_pinned_mut()
            .write_all(b"ping")
            .await
            .expect("write through tunnel");
        let mut echo = [0_u8; 4];
        tunnel
            .as_pinned_mut()
            .read_exact(&mut echo)
            .await
            .expect("echo through tunnel");
        assert_eq!(&echo, b"ping");
    }

    #[tokio::test]
    async fn upgrade_with_unexpected_protocol_is_502() {
        // Upstream answers 101 with a different protocol than the client requested.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let _head = read_http_head(&mut stream).await;
            let response = "HTTP/1.1 101 Switching Protocols\r\n\
                            Connection: Upgrade\r\n\
                            Upgrade: h2c\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        let handler = handler(&address.to_string());
        let outcome = handler
            .handle_streaming(upgrade_request("/ws"))
            .await
            .expect("a failed upgrade is a response");
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a 502 response, got an upgrade");
        };
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        let body = response.body.into_bytes().await.expect("502 body");
        assert_eq!(body, Bytes::from_static(b"502 Bad Gateway"));
    }

    #[tokio::test]
    async fn buffered_handler_rejects_upgrade_loudly() {
        let dial = spawn_upgrade_echo_upstream().await;
        let handler = handler(&dial);
        let error = handler
            .handle(upgrade_request("/ws"))
            .await
            .expect_err("buffered path cannot carry a tunnel");
        assert!(
            matches!(error, HttpError::UpgradeNotRepresentable { .. }),
            "expected UpgradeNotRepresentable, got {error:?}"
        );
    }

    #[tokio::test]
    async fn non_upgrade_requests_still_proxy_normally() {
        let dial = spawn_upgrade_echo_upstream().await;
        let handler = handler(&dial);
        let mut request = Request::new(Method::GET, "/plain".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let outcome = handler
            .handle_streaming(request)
            .await
            .expect("normal response");
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a normal response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body.into_bytes().await.unwrap(),
            Bytes::from_static(b"plain")
        );
    }

    #[tokio::test]
    async fn tunnel_drop_closes_the_upstream_connection() {
        let dial = spawn_upgrade_echo_upstream().await;
        let handler = handler(&dial);
        let outcome = handler
            .handle_streaming(upgrade_request("/ws"))
            .await
            .expect("upgrade handshake");
        let StreamingOutcome::Upgrade(UpgradedResponse { tunnel, .. }) = outcome else {
            panic!("expected an upgraded outcome");
        };
        let mut tunnel: Tunnel = tunnel;
        let mut greeting = [0_u8; 8];
        tunnel
            .as_pinned_mut()
            .read_exact(&mut greeting)
            .await
            .expect("greeting");
        // Dropping the tunnel closes the upstream connection; the raw upstream echoes until EOF and
        // then returns, which is the observable close propagation for this test.
        drop(tunnel);
    }
}

#[cfg(test)]
mod h2_tests {
    //! HTTP/2 / h2c upstream transport tests: ALPN negotiation, h1 fallback, prior knowledge,
    //! streaming, health checks and the h1-only companion used for protocol upgrades.

    use super::*;
    use bytes::Bytes;
    use caddy_rs_http::body::{BodyError, StreamingBody};
    use http::{Method, StatusCode, Version};
    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tokio_rustls::TlsAcceptor;

    const CERT: &str = include_str!("../testdata/tls/localhost-cert.pem");
    const KEY: &str = include_str!("../testdata/tls/localhost-key.pem");

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Seen {
        Http1,
        Http2,
    }

    type SeenList = Arc<Mutex<Vec<Seen>>>;

    fn tls_acceptor(alpn: Vec<Vec<u8>>) -> TlsAcceptor {
        let certificates = crate::tls::parse_pem_certificates(CERT.as_bytes()).unwrap();
        let key = crate::tls::parse_pem_private_key(KEY.as_bytes()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = alpn;
        TlsAcceptor::from(Arc::new(config))
    }

    fn record_version(request: &hyper::Request<hyper::body::Incoming>, seen: &SeenList) -> Seen {
        let version = if request.version() == Version::HTTP_2 {
            Seen::Http2
        } else {
            Seen::Http1
        };
        seen.lock().unwrap().push(version);
        version
    }

    fn version_response(
        request: &hyper::Request<hyper::body::Incoming>,
        seen: &SeenList,
    ) -> hyper::Response<Full<Bytes>> {
        let _ = record_version(request, seen);
        let body = format!(
            "version={:?} path={} authority={} host={}",
            request.version(),
            request.uri().path(),
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
                .unwrap_or("missing"),
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("missing"),
        );
        hyper::Response::builder()
            .status(200)
            .header("x-server-version", format!("{:?}", request.version()))
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// TLS upstream that serves h1 or h2 depending on the negotiated ALPN protocol and records
    /// every request's HTTP version.
    async fn spawn_tls_versioned_upstream(alpn: Vec<Vec<u8>>, seen: SeenList) -> String {
        let acceptor = tls_acceptor(alpn);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request| {
                        let seen = Arc::clone(&seen);
                        async move { Ok::<_, Infallible>(version_response(&request, &seen)) }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    /// Cleartext upstream that auto-detects HTTP/1.1 vs HTTP/2 prior-knowledge connections.
    async fn spawn_plain_versioned_upstream(seen: SeenList) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let seen = Arc::clone(&seen);
                        async move { Ok::<_, Infallible>(version_response(&request, &seen)) }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    /// Cleartext upstream over a Unix socket (auto-detects h1/h2 prior knowledge).
    #[cfg(unix)]
    async fn spawn_unix_versioned_upstream(socket: std::path::PathBuf, seen: SeenList) -> () {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let seen = Arc::clone(&seen);
                        async move { Ok::<_, Infallible>(version_response(&request, &seen)) }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
    }

    /// TLS HTTP/2 upstream with a channel-fed streaming body (for streaming tests).
    async fn spawn_tls_h2_channel_upstream() -> (
        String,
        tokio::sync::mpsc::Sender<std::result::Result<Bytes, BodyError>>,
    ) {
        let acceptor = tls_acceptor(vec![b"h2".to_vec()]);
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        let receiver = Arc::new(Mutex::new(Some(receiver)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = service_fn(move |_request| {
                let receiver = Arc::clone(&receiver);
                async move {
                    let receiver = receiver
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                        .expect("one streaming request per test upstream");
                    Ok::<_, Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .header("content-type", "text/event-stream")
                            .body(StreamingBody::from_chunks(receiver))
                            .expect("streaming response"),
                    )
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
        (address.to_string(), sender)
    }

    fn write_root(directory: &tempfile::TempDir) -> String {
        let path = directory.path().join("root-ca.pem");
        std::fs::write(&path, CERT).unwrap();
        path.display().to_string()
    }

    fn build(value: Value) -> ReverseProxyHandler {
        ReverseProxyHandler::from_json(&value, "handler").expect("handler builds")
    }

    fn tls_handler(
        dial: &str,
        root: &str,
        versions: Option<&[&str]>,
        health_check: bool,
    ) -> ReverseProxyHandler {
        let mut transport = serde_json::json!({
            "protocol": "http",
            "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
        });
        if let Some(versions) = versions {
            transport["versions"] = serde_json::json!(versions);
        }
        let mut config = serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": transport
        });
        if health_check {
            config["health_checks"] = serde_json::json!({"active": {"uri": "/health"}});
        }
        build(config)
    }

    fn plain_handler(dial: &str, versions: &[&str]) -> ReverseProxyHandler {
        build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "transport": {"protocol": "http", "versions": versions}
        }))
    }

    fn get(path: &str) -> Request {
        let mut request = Request::new(Method::GET, path.parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
    }

    fn body_string(response: &Response) -> String {
        String::from_utf8(response.body.to_vec()).unwrap()
    }

    async fn respond(handler: &ReverseProxyHandler, path: &str) -> Response {
        let Outcome::Respond(response) = handler.handle(get(path)).await.unwrap() else {
            panic!("expected proxied response");
        };
        response
    }

    #[tokio::test]
    async fn tls_h2_upstream_selected_via_alpn() {
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(vec![b"h2".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), false);

        let response = respond(&handler, "/over-h2").await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(body_string(&response).contains("version=HTTP/2.0"));
        assert_eq!(response.headers["x-server-version"], "HTTP/2.0");
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
        assert_eq!(response.headers[http::header::VIA], "2.0 Caddy");
    }

    #[tokio::test]
    async fn tls_mixed_versions_fall_back_to_http1() {
        // The client offers h2+http/1.1; this upstream only speaks http/1.1.
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial =
            spawn_tls_versioned_upstream(vec![b"http/1.1".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["1.1", "2"]), false);

        let response = respond(&handler, "/fallback").await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(body_string(&response).contains("version=HTTP/1.1"));
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http1]);
        assert_eq!(response.headers[http::header::VIA], "1.1 Caddy");
    }

    #[tokio::test]
    async fn tls_default_versions_negotiate_h2() {
        // Caddy's default versions are ["1.1","2"] even when the field is absent; TLS ALPN
        // therefore offers h2 first and the server selects it.
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Arc::clone(&seen),
        )
        .await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, None, false);

        let response = respond(&handler, "/defaults").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn h2c_prior_knowledge_upstream() {
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_plain_versioned_upstream(Arc::clone(&seen)).await;
        let handler = plain_handler(&dial, &["h2c"]);

        let response = respond(&handler, "/cleartext-h2").await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(body_string(&response).contains("version=HTTP/2.0"));
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn h2c_pair_versions_from_caddy_h2c_transport() {
        // Caddy's `http.transport.h2c` transport enables versions ["h2c","2"].
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_plain_versioned_upstream(Arc::clone(&seen)).await;
        let handler = plain_handler(&dial, &["h2c", "2"]);

        let response = respond(&handler, "/cleartext-h2-pair").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn plaintext_version_two_without_h2c_stays_http1() {
        // Go's plaintext transport is HTTP/1.1 even when "2" is listed; h2c requires "h2c".
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_plain_versioned_upstream(Arc::clone(&seen)).await;
        let handler = plain_handler(&dial, &["2"]);

        let response = respond(&handler, "/plain-h1").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http1]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn h2c_prior_knowledge_over_unix_socket() {
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("h2c.sock");
        spawn_unix_versioned_upstream(socket.clone(), Arc::clone(&seen)).await;
        let dial = format!("unix/{}", socket.display());
        let handler = plain_handler(&dial, &["h2c"]);

        let response = respond(&handler, "/unix-h2c").await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(body_string(&response).contains("version=HTTP/2.0"));
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn h2_authority_uses_original_host_without_a_separate_host_field() {
        // T-PROXY-041: the original request Host becomes HTTP/2 `:authority` (Caddy/Go parity),
        // while the connector still dials the configured upstream. No separate Host field is sent.
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(vec![b"h2".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), false);

        let response = respond(&handler, "/authority").await;
        let body = body_string(&response);
        assert!(body.contains("version=HTTP/2.0"), "{body}");
        assert!(
            body.contains("authority=example.com"),
            "h2 :authority must be the original Host, not the dial: {body}"
        );
        assert!(
            body.contains("host=missing"),
            "no separate Host field should accompany h2 :authority: {body}"
        );
        // The request still reached the bound dial target (the server we spawned above).
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn h2_authority_tracks_a_host_different_from_the_dial() {
        // Mismatch case: Host (app.example.com) differs from the dial host (127.0.0.1). The
        // `:authority` must be the Host; the connection must still go to the dialed upstream.
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(vec![b"h2".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), false);

        let mut request = get("/mismatch");
        request
            .headers
            .insert(http::header::HOST, "app.example.com".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        let body = body_string(&response);
        assert!(body.contains("authority=app.example.com"), "{body}");
        assert!(body.contains("host=missing"), "{body}");
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn h1_fallback_keeps_host_field_from_the_uri_authority() {
        // On the HTTP/1.1 fallback path the same URI authority becomes the auto-generated Host
        // field (the explicit Host was removed for h2-capable transports).
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial =
            spawn_tls_versioned_upstream(vec![b"http/1.1".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["1.1", "2"]), false);

        let response = respond(&handler, "/h1-fallback").await;
        let body = body_string(&response);
        assert!(body.contains("version=HTTP/1.1"), "{body}");
        assert!(body.contains("host=example.com"), "{body}");
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http1]);
    }

    #[tokio::test]
    async fn h2_authority_over_unix_socket_tls_upstream() {
        #[cfg(not(unix))]
        return;
        #[cfg(unix)]
        {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("h2-tls.sock");
            let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
            let acceptor = tls_acceptor(vec![b"h2".to_vec()]);
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let seen_server = Arc::clone(&seen);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let seen = Arc::clone(&seen_server);
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let service = service_fn(move |request| {
                            let seen = Arc::clone(&seen);
                            async move { Ok::<_, Infallible>(version_response(&request, &seen)) }
                        });
                        let _ = auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
            let root_dir = tempfile::tempdir().unwrap();
            let root = write_root(&root_dir);
            let dial = format!("unix/{}", socket.display());
            let handler = build(serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "transport": {
                    "protocol": "http",
                    "versions": ["2"],
                    "tls": {"root_ca_pem_files": [root], "server_name": "localhost"}
                }
            }));
            let response = respond(&handler, "/unix-h2").await;
            let body = body_string(&response);
            assert!(body.contains("version=HTTP/2.0"), "{body}");
            assert!(body.contains("authority=example.com"), "{body}");
            assert!(body.contains("host=missing"), "{body}");
            assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
        }
    }

    #[tokio::test]
    async fn h2c_authority_uses_original_host() {
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_plain_versioned_upstream(Arc::clone(&seen)).await;
        let handler = plain_handler(&dial, &["h2c"]);
        let response = respond(&handler, "/h2c-authority").await;
        let body = body_string(&response);
        assert!(body.contains("version=HTTP/2.0"), "{body}");
        assert!(body.contains("authority=example.com"), "{body}");
        assert!(body.contains("host=missing"), "{body}");
    }

    #[tokio::test]
    async fn streaming_response_over_h2() {
        let (dial, sender) = spawn_tls_h2_channel_upstream().await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), false);

        let outcome = handler.handle_streaming(get("/h2-stream")).await.unwrap();
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.is_streaming(), "response body must stream over h2");
        let mut body = match response.body {
            Body::Stream(stream) => stream,
            Body::Bytes(_) => panic!("expected a streaming body"),
        };

        sender
            .send(Ok(Bytes::from_static(b"data: first\n\n")))
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("first frame timeout")
            .expect("first frame")
            .expect("data");
        assert_eq!(
            first.into_data().unwrap(),
            Bytes::from_static(b"data: first\n\n")
        );
        assert!(!sender.is_closed(), "h2 stream must not be buffered");

        sender
            .send(Ok(Bytes::from_static(b"data: second\n\n")))
            .await
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("second frame timeout")
            .expect("second frame")
            .expect("data");
        assert_eq!(
            second.into_data().unwrap(),
            Bytes::from_static(b"data: second\n\n")
        );
    }

    #[tokio::test]
    async fn health_check_over_h2_upstream() {
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(vec![b"h2".to_vec()], Arc::clone(&seen)).await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), true);

        let check = handler
            .health_check()
            .expect("active health check configured");
        assert!(
            check
                .check_once(handler.client(), &handler.upstreams()[0])
                .await,
            "health check should succeed over HTTP/2"
        );
        assert_eq!(*seen.lock().unwrap(), vec![Seen::Http2]);
    }

    #[tokio::test]
    async fn upgrade_requests_use_h1_companion_when_http2_enabled() {
        // Server supports both; the main client negotiates h2, but an upgrade request must use
        // HTTP/1.1 (protocol upgrades cannot be carried over HTTP/2).
        let seen: SeenList = Arc::new(Mutex::new(Vec::new()));
        let dial = spawn_tls_versioned_upstream(
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Arc::clone(&seen),
        )
        .await;
        let directory = tempfile::tempdir().unwrap();
        let root = write_root(&directory);
        let handler = tls_handler(&dial, &root, Some(&["2"]), false);

        // Normal request: h2.
        assert_eq!(respond(&handler, "/normal").await.status, StatusCode::OK);

        // Upgrade request: server sees an HTTP/1.1 connection because the companion client
        // advertises only http/1.1. The server answers 200 (no real upgrade), which the proxy
        // passes through.
        let mut upgrade = get("/upgrade");
        upgrade
            .headers
            .insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        upgrade
            .headers
            .insert(http::header::UPGRADE, "websocket".parse().unwrap());
        upgrade.headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        upgrade
            .headers
            .insert("sec-websocket-version", "13".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(upgrade).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![Seen::Http2, Seen::Http1],
            "upgrade request must use the h1-only companion client"
        );
    }
}

#[cfg(test)]
mod body_tests {
    //! Request-body forwarding (T-PROXY-040 / T-PROXY-039 proxy half).
    //!
    //! Policy under test: retry-capable handlers (`retries`/`try_duration`) and `handle_response`
    //! handlers buffer the body once and replay it per attempt; everything else streams the body
    //! exactly once via `Request::take_body`, never forwarding a silently empty body. A second
    //! streaming attempt fails loudly.

    use super::*;
    use bytes::{Bytes, BytesMut};
    use caddy_rs_http::body::{BodyError, RequestBody, StreamingBody};
    use http::{Method, StatusCode};
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    #[derive(Debug, Clone, Default)]
    struct CapturedBody {
        body: Bytes,
        chunks: usize,
        content_length: Option<String>,
        transfer_encoding: Option<String>,
    }

    /// Upstream that captures the request body frame-by-frame and signals when the first data
    /// frame arrives (proving the proxy streams rather than buffering).
    async fn spawn_body_capture_upstream(
    ) -> (String, Arc<Mutex<Option<CapturedBody>>>, mpsc::Receiver<()>) {
        let captured = Arc::new(Mutex::new(None::<CapturedBody>));
        let (first_tx, first_rx) = mpsc::channel(1);
        let first_tx = Arc::new(Mutex::new(Some(first_tx)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured_server = Arc::clone(&captured);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let captured = Arc::clone(&captured_server);
                let first_tx = Arc::clone(&first_tx);
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let captured = Arc::clone(&captured);
                            let first_tx = Arc::clone(&first_tx);
                            async move {
                                let content_length = request
                                    .headers()
                                    .get(http::header::CONTENT_LENGTH)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string);
                                let transfer_encoding = request
                                    .headers()
                                    .get(http::header::TRANSFER_ENCODING)
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string);
                                let mut body = request.into_body();
                                let mut buffer = BytesMut::new();
                                let mut chunks = 0_usize;
                                while let Some(frame) = body.frame().await {
                                    let Ok(frame) = frame else {
                                        break;
                                    };
                                    let Ok(data) = frame.into_data() else {
                                        continue;
                                    };
                                    if data.is_empty() {
                                        continue;
                                    }
                                    chunks += 1;
                                    if chunks == 1 {
                                        let sender = first_tx
                                            .lock()
                                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                                            .take();
                                        if let Some(sender) = sender {
                                            let _ = sender.send(()).await;
                                        }
                                    }
                                    buffer.extend_from_slice(&data);
                                }
                                let body = buffer.freeze();
                                *captured
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                                    Some(CapturedBody {
                                        body: body.clone(),
                                        chunks,
                                        content_length,
                                        transfer_encoding,
                                    });
                                let response_body = format!("len={}", body.len());
                                Ok::<_, Infallible>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("x-chunks", chunks.to_string())
                                        .body(Full::new(Bytes::from(response_body)))
                                        .expect("response"),
                                )
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (address.to_string(), captured, first_rx)
    }

    fn build(value: Value) -> ReverseProxyHandler {
        ReverseProxyHandler::from_json(&value, "handler").expect("handler builds")
    }

    fn proxy(dial: &str) -> ReverseProxyHandler {
        build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}]
        }))
    }

    fn post_request(path: &str) -> Request {
        let mut request = Request::new(Method::POST, path.parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
    }

    fn streaming_request(
        path: &str,
    ) -> (Request, mpsc::Sender<std::result::Result<Bytes, BodyError>>) {
        let (sender, receiver) = mpsc::channel(8);
        let request = post_request(path)
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        (request, sender)
    }

    fn captured(captured: &Arc<Mutex<Option<CapturedBody>>>) -> CapturedBody {
        captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .expect("upstream captured a body")
    }

    #[test]
    fn body_buffering_policy_matches_retry_capability() {
        // Nothing retry-like configured: stream.
        assert!(!proxy("localhost:8080").requires_buffered_request_body());
        // retries > 0: buffer once for replay.
        let retrying = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "load_balancing": {"retries": 1}
        }));
        assert!(retrying.requires_buffered_request_body());
        // try_duration-only retry budget: buffer.
        let duration = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "load_balancing": {"try_duration": 1_000_000u64}
        }));
        assert!(duration.requires_buffered_request_body());
        // handle_response may continue the chain / replay: buffer.
        let response = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "handle_response": [{"routes": []}]
        }));
        assert!(response.requires_buffered_request_body());
        // retry_match without any retry budget can never retry: keep streaming.
        let match_only = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "localhost:8080"}],
            "load_balancing": {"retry_match": [{"method": ["GET"]}]}
        }));
        assert!(!match_only.requires_buffered_request_body());
    }

    #[tokio::test]
    async fn streaming_request_body_is_forwarded_once_without_buffering() {
        let (dial, captured_body, mut first_chunk) = spawn_body_capture_upstream().await;
        let handler = proxy(&dial);
        assert!(!handler.requires_buffered_request_body());
        let (request, sender) = streaming_request("/upload");

        let call = tokio::spawn(async move { handler.handle(request).await });
        // First chunk reaches the upstream while the client body stream is still open: the proxy
        // did not buffer the whole body.
        sender
            .send(Ok(Bytes::from_static(b"first-chunk-")))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), first_chunk.recv())
            .await
            .expect("upstream must observe the first chunk before the body finishes")
            .expect("first-chunk signal");
        assert!(!sender.is_closed(), "client body stream must still be open");

        sender
            .send(Ok(Bytes::from_static(b"second-chunk")))
            .await
            .unwrap();
        drop(sender);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .expect("proxy call timed out")
            .expect("handler task panicked")
            .expect("handler result");
        let Outcome::Respond(response) = outcome else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);

        let captured_body = captured(&captured_body);
        assert_eq!(
            captured_body.body,
            Bytes::from_static(b"first-chunk-second-chunk"),
            "the streamed body must arrive intact (never a silent empty body)"
        );
        assert_eq!(
            captured_body.chunks, 2,
            "h1 chunked forwarding keeps frames"
        );
        assert_eq!(
            captured_body.content_length, None,
            "an unknown-length streamed body is forwarded chunked, not with a made-up length"
        );
        assert_eq!(
            captured_body.transfer_encoding.as_deref(),
            Some("chunked"),
            "streamed bodies use chunked transfer encoding"
        );
    }

    #[tokio::test]
    async fn buffered_request_body_is_forwarded_with_content_length() {
        let (dial, captured_body, _first_chunk) = spawn_body_capture_upstream().await;
        let handler = proxy(&dial);
        let mut request = post_request("/buffered");
        request.body = Bytes::from_static(b"hello buffered body");
        request
            .headers
            .insert(http::header::CONTENT_LENGTH, "19".parse().unwrap());

        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        let captured_body = captured(&captured_body);
        assert_eq!(
            captured_body.body,
            Bytes::from_static(b"hello buffered body")
        );
        assert_eq!(
            captured_body.content_length.as_deref(),
            Some("19"),
            "buffered bodies keep their Content-Length"
        );
        assert_eq!(captured_body.transfer_encoding, None);
    }

    #[tokio::test]
    async fn retry_capable_handler_replays_the_streamed_body_on_a_dial_failure() {
        // Reserve a closed port so the first selected upstream fails to dial.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let (good_dial, captured_body, _first_chunk) = spawn_body_capture_upstream().await;
        let handler = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dead_dial}, {"dial": good_dial}],
            "load_balancing": {"retries": 1}
        }));
        assert!(handler.requires_buffered_request_body());

        let (request, sender) = streaming_request("/replayed");
        sender
            .send(Ok(Bytes::from_static(b"replay-me-")))
            .await
            .unwrap();
        sender.send(Ok(Bytes::from_static(b"twice"))).await.unwrap();
        drop(sender);

        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        let captured_body = captured(&captured_body);
        assert_eq!(
            captured_body.body,
            Bytes::from_static(b"replay-me-twice"),
            "the buffered body must be replayed on the retry attempt"
        );
        assert_eq!(
            captured_body.content_length.as_deref(),
            Some("15"),
            "a replayed buffered body has a known length"
        );
    }

    #[tokio::test]
    async fn buffered_policy_maps_an_oversized_streamed_body_to_413() {
        // A retry-capable handler buffers the body; if collecting it trips the configured limit
        // (server-side request-body limit carried on RequestBody) the proxy must surface 413, not
        // forward a truncated body or a misleading 502.
        let (dial, _captured_body, _first_chunk) = spawn_body_capture_upstream().await;
        let handler = build(serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": dial}],
            "load_balancing": {"retries": 1}
        }));
        let (sender, receiver) = mpsc::channel(8);
        let body = RequestBody::streaming(StreamingBody::from_chunks(receiver)).with_limit(Some(4));
        let mut request = post_request("/too-large").with_streaming_body(body);
        let _ = &mut request;
        sender.send(Ok(Bytes::from_static(b"1234"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"5"))).await.unwrap();
        drop(sender);

        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected a response");
        };
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn a_second_streaming_attempt_fails_loudly_instead_of_sending_an_empty_body() {
        let handler = proxy("localhost:8080");
        let (mut request, _sender) = streaming_request("/once");
        let mut stream_taken = false;
        assert!(
            handler
                .attempt_body(&mut request, false, &mut stream_taken)
                .is_ok(),
            "the first attempt takes the streaming body"
        );
        let error = handler
            .attempt_body(&mut request, false, &mut stream_taken)
            .expect_err("a second streaming attempt cannot be replayed");
        assert!(error.contains("already streamed"), "{error}");
        assert!(error.contains("cannot be replayed"), "{error}");
    }
}

#[cfg(test)]
mod tls_client_tests {
    //! Upstream mutual-TLS client certificates, `ca` module trust roots, and `except_ports`.

    use super::*;
    use caddy_rs_http::Handler;
    use http::{Method, StatusCode};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tokio_rustls::TlsAcceptor;

    const SERVER_CERT: &str = include_str!("../testdata/tls/localhost-cert.pem");
    const SERVER_KEY: &str = include_str!("../testdata/tls/localhost-key.pem");
    const CLIENT_CA: &str = include_str!("../testdata/tls/client-ca-cert.pem");
    const CLIENT_CERT: &str = include_str!("../testdata/tls/client-cert.pem");
    const CLIENT_KEY: &str = include_str!("../testdata/tls/client-key.pem");

    fn write_fixture(directory: &tempfile::TempDir, name: &str, contents: &str) -> String {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path.display().to_string()
    }

    fn server_identity() -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let certificates = crate::tls::parse_pem_certificates(SERVER_CERT.as_bytes()).unwrap();
        let key = crate::tls::parse_pem_private_key(SERVER_KEY.as_bytes()).unwrap();
        (certificates, key)
    }

    /// TLS server that requires a client certificate signed by `client-ca-cert.pem`.
    fn mtls_acceptor(alpn: Vec<Vec<u8>>) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for certificate in crate::tls::parse_pem_certificates(CLIENT_CA.as_bytes()).unwrap() {
            roots.add(certificate).unwrap();
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier builds");
        let (certificates, key) = server_identity();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = alpn;
        TlsAcceptor::from(Arc::new(config))
    }

    /// TLS server that does not require a client certificate.
    fn tls_acceptor(alpn: Vec<Vec<u8>>) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (certificates, key) = server_identity();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = alpn;
        TlsAcceptor::from(Arc::new(config))
    }

    async fn spawn_tls_upstream(acceptor: TlsAcceptor) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
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
                            let body = format!(
                                "version={:?} path={}",
                                request.version(),
                                request.uri().path()
                            );
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-transport", "tls")
                                    .body(Full::new(Bytes::from(body)))
                                    .expect("response"),
                            )
                        },
                    );
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    async fn spawn_plain_upstream() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(
                        |_request: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-transport", "plain")
                                    .body(Full::new(Bytes::from_static(b"plain-h1")))
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
        address.to_string()
    }

    fn build_handler(dial: &str, tls: Value, versions: Option<&[&str]>) -> ReverseProxyHandler {
        let mut transport = serde_json::json!({"protocol": "http", "tls": tls});
        if let Some(versions) = versions {
            transport["versions"] = serde_json::json!(versions);
        }
        ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "transport": transport
            }),
            "handler",
        )
        .expect("handler builds")
    }

    fn get(path: &str) -> Request {
        let mut request = Request::new(Method::GET, path.parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
    }

    fn body_string(response: &Response) -> String {
        String::from_utf8(response.body.to_vec()).unwrap()
    }

    fn respond(handler: &ReverseProxyHandler, request: Request) -> Response {
        let outcome = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(handler.handle(request))
        });
        let Outcome::Respond(response) = outcome.expect("handler result") else {
            panic!("expected proxied response");
        };
        response
    }

    fn tls_with_client_identity(root: &str, client_cert: &str, client_key: &str) -> Value {
        serde_json::json!({
            "root_ca_pem_files": [root],
            "server_name": "localhost",
            "client_certificate_file": client_cert,
            "client_certificate_key_file": client_key
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_client_certificate_authenticates() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let cert = write_fixture(&directory, "client.pem", CLIENT_CERT);
        let key = write_fixture(&directory, "client-key.pem", CLIENT_KEY);
        let dial = spawn_tls_upstream(mtls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(&dial, tls_with_client_identity(&root, &cert, &key), None);
        let response = respond(&handler, get("/mtls"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "tls");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_without_client_certificate_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let dial = spawn_tls_upstream(mtls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "root_ca_pem_files": [root],
                "server_name": "localhost"
            }),
            None,
        );
        let response = respond(&handler, get("/mtls"));
        assert_eq!(
            response.status,
            StatusCode::BAD_GATEWAY,
            "the server requires a client certificate"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_with_wrong_client_certificate_is_rejected() {
        // The server trusts only client certs signed by `client-ca-cert.pem`; presenting the
        // (self-signed) server identity as the client certificate must be rejected.
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let wrong_cert = write_fixture(&directory, "wrong-client.pem", SERVER_CERT);
        let wrong_key = write_fixture(&directory, "wrong-client-key.pem", SERVER_KEY);
        let dial = spawn_tls_upstream(mtls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            tls_with_client_identity(&root, &wrong_cert, &wrong_key),
            None,
        );
        let response = respond(&handler, get("/mtls"));
        assert_eq!(
            response.status,
            StatusCode::BAD_GATEWAY,
            "an untrusted client certificate must fail the handshake"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_certificate_negotiates_http2() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let cert = write_fixture(&directory, "client.pem", CLIENT_CERT);
        let key = write_fixture(&directory, "client-key.pem", CLIENT_KEY);
        let dial = spawn_tls_upstream(mtls_acceptor(vec![b"h2".to_vec()])).await;
        let handler = build_handler(
            &dial,
            tls_with_client_identity(&root, &cert, &key),
            Some(&["2"]),
        );
        let response = respond(&handler, get("/mtls-h2"));
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            body_string(&response).contains("version=HTTP/2.0"),
            "client-certificate mTLS should still negotiate HTTP/2"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ca_module_file_provider_trusts_server() {
        let directory = tempfile::tempdir().unwrap();
        let ca = write_fixture(&directory, "ca.pem", SERVER_CERT);
        let dial = spawn_tls_upstream(tls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "ca": {"provider": "file", "pem_files": [ca]},
                "server_name": "localhost"
            }),
            None,
        );
        let response = respond(&handler, get("/ca-file"));
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ca_module_inline_provider_trusts_server() {
        let certificate = crate::tls::parse_pem_certificates(SERVER_CERT.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let encoded = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(certificate.as_ref())
        };
        let dial = spawn_tls_upstream(tls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "ca": {"provider": "inline", "trusted_ca_certs": [encoded]},
                "server_name": "localhost"
            }),
            None,
        );
        let response = respond(&handler, get("/ca-inline"));
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ca_module_and_client_certificate_combine_for_mtls() {
        // The `ca` module replaces the deprecated root options for server verification; the client
        // certificate still authenticates to the mTLS server.
        let directory = tempfile::tempdir().unwrap();
        let ca = write_fixture(&directory, "ca.pem", SERVER_CERT);
        let cert = write_fixture(&directory, "client.pem", CLIENT_CERT);
        let key = write_fixture(&directory, "client-key.pem", CLIENT_KEY);
        let dial = spawn_tls_upstream(mtls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "ca": {"provider": "file", "pem_files": [ca]},
                "server_name": "localhost",
                "client_certificate_file": cert,
                "client_certificate_key_file": key
            }),
            None,
        );
        let response = respond(&handler, get("/ca-mtls"));
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn except_ports_skips_tls_for_matching_port() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let dial = spawn_plain_upstream().await;
        let port = dial.rsplit_once(':').unwrap().1;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "root_ca_pem_files": [root],
                "server_name": "localhost",
                "except_ports": [port]
            }),
            None,
        );
        assert!(
            !handler.upstreams()[0].tls,
            "the excepted upstream must be dialed without TLS"
        );
        let response = respond(&handler, get("/plain"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "plain");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn except_ports_does_not_skip_tls_for_other_ports() {
        let directory = tempfile::tempdir().unwrap();
        let root = write_fixture(&directory, "root.pem", SERVER_CERT);
        let dial = spawn_tls_upstream(tls_acceptor(vec![b"http/1.1".to_vec()])).await;
        let handler = build_handler(
            &dial,
            serde_json::json!({
                "root_ca_pem_files": [root],
                "server_name": "localhost",
                "except_ports": ["9"]
            }),
            None,
        );
        assert!(handler.upstreams()[0].tls);
        let response = respond(&handler, get("/tls"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers["x-transport"], "tls");
    }

    #[test]
    fn except_ports_and_client_cert_fields_are_parsed_from_transport() {
        let handler = build_handler(
            "127.0.0.1:9000",
            serde_json::json!({
                "insecure_skip_verify": true,
                "except_ports": ["8080"]
            }),
            None,
        );
        // 9000 is not excepted, so the upstream still uses TLS.
        assert!(handler.upstreams()[0].tls);
        assert!(!handler.upstreams()[0].is_full());
    }

    #[test]
    fn except_ports_with_fastcgi_is_rejected() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}],
                "transport": {"protocol": "fastcgi", "except_ports": ["8080"]}
            }),
            "handler",
        )
        .err()
        .expect("except_ports is not a fastcgi transport option");
        assert!(error.to_string().contains("except_ports"), "{error}");
    }
}
