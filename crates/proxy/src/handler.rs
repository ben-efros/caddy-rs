//! The `reverse_proxy` handler.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value;

use caddy_rs_http::{
    CustomHandlerFactory, Error as HttpError, Handler, Outcome, Request, Response,
    Result as HttpResult,
};

use crate::balancer::{self, Balancer};
use crate::client::{build_client, HttpClient};
use crate::health::HealthCheck;
use crate::upstream::Upstream;

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
    fail_duration: Duration,
    health_check: Option<Arc<HealthCheck>>,
}

impl ReverseProxyHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "reverse_proxy handler must be an object"))?;

        let transport = object.get("transport");
        let transport_tls = transport
            .and_then(|transport| transport.get("tls"))
            .is_some();
        if transport
            .and_then(|transport| transport.get("versions"))
            .is_some()
        {
            return Err(HttpError::NotImplemented {
                feature: "HTTP/2 upstream transports (h2c/h2)",
                tracking_id: "PROXY-H2-UPSTREAM",
            });
        }
        if transport_tls {
            return Err(HttpError::NotImplemented {
                feature:
                    "TLS upstreams (rustls client trust configuration unavailable in this build)",
                tracking_id: "TLS-UPSTREAM",
            });
        }

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
            let parsed = Upstream::parse_dial(dial, false)
                .map_err(|message| invalid(&upstream_path, message))?;
            upstreams.push(Arc::new(parsed));
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

        let fail_duration = object
            .get("fail_duration")
            .and_then(Value::as_u64)
            .map(Duration::from_nanos)
            .unwrap_or_else(|| Duration::from_secs(10));

        let (
            request_headers_set,
            response_headers_set,
            response_headers_add,
            response_headers_delete,
        ) = parse_headers(object.get("headers"), path)?;

        let health_check = parse_health_check(object, path)?;

        Ok(Self {
            client: build_client(),
            upstreams,
            balancer,
            request_headers_set,
            response_headers_set,
            response_headers_add,
            response_headers_delete,
            retries,
            try_duration,
            try_interval,
            fail_duration,
            health_check,
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

    async fn forward(
        &self,
        upstream: &Upstream,
        request: &Request,
    ) -> Result<Response, ProxyError> {
        let path_and_query = request
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let url = format!("http://{}{}", upstream.dial, path_and_query);
        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            if is_hop_by_hop(name) || name == http::header::HOST {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(&upstream.dial)
                .map_err(|error| ProxyError::Request(error.to_string()))?,
        );
        if let Some(remote) = request.remote_addr {
            let forwarded = headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .map(|existing| format!("{existing}, {}", remote.ip()))
                .unwrap_or_else(|| remote.ip().to_string());
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&forwarded)
                    .map_err(|error| ProxyError::Request(error.to_string()))?,
            );
        }
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if request.tls { "https" } else { "http" }),
        );
        if let Some(host) = request.host() {
            if let Ok(value) = HeaderValue::from_str(host) {
                headers.insert("x-forwarded-host", value);
            }
        }
        for (name, value) in &self.request_headers_set {
            headers.insert(name.clone(), value.clone());
        }

        let outbound = hyper::Request::builder()
            .method(request.method.clone())
            .uri(url)
            .body(Full::new(request.body.clone()))
            .map_err(|error| ProxyError::Request(error.to_string()))?;
        let mut outbound = outbound;
        *outbound.headers_mut() = headers;

        let response = self.client.request(outbound).await?;
        let status = response.status();
        let response_headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ProxyError::Body(error.to_string()))?
            .to_bytes();
        let mut headers = HeaderMap::new();
        for (name, value) in &response_headers {
            if is_hop_by_hop(name) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        Ok(Response {
            status,
            headers,
            body,
        })
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

    fn schedule_recovery(&self, upstream: Arc<Upstream>) {
        let fail_duration = self.fail_duration;
        tokio::spawn(async move {
            tokio::time::sleep(fail_duration).await;
            upstream.set_healthy(true);
        });
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
        let mut attempts: u32 = 0;
        loop {
            let Some(upstream) = self.balancer.select(&self.upstreams) else {
                // No upstream has ever been tried: the pool is empty or all are marked down.
                // After a failed attempt the gateway semantics are 502, matching Caddy's
                // "upstream unavailable after retries" behaviour.
                let (status, body) = if attempts == 0 {
                    (StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable")
                } else {
                    (StatusCode::BAD_GATEWAY, "502 Bad Gateway")
                };
                return Ok(Outcome::Respond(Response::text(status, body)));
            };
            let _guard = upstream.connection_started();
            match self.forward(&upstream, &request).await {
                Ok(mut response) => {
                    self.apply_response_headers(&mut response);
                    return Ok(Outcome::Respond(response));
                }
                Err(error) => {
                    eprintln!(
                        "caddy-rs: reverse_proxy upstream `{}` failed: {error}",
                        upstream.dial
                    );
                    upstream.set_healthy(false);
                    self.schedule_recovery(Arc::clone(&upstream));
                    attempts += 1;
                    let past_deadline =
                        deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline);
                    if attempts > self.retries || past_deadline {
                        return Ok(Outcome::Respond(Response::text(
                            StatusCode::BAD_GATEWAY,
                            "502 Bad Gateway",
                        )));
                    }
                    if !self.try_interval.is_zero() {
                        tokio::time::sleep(self.try_interval).await;
                    }
                }
            }
        }
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
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

fn parse_health_check(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<Option<Arc<HealthCheck>>> {
    let uri = object.get("health_uri").and_then(Value::as_str);
    let interval = object
        .get("health_interval")
        .and_then(Value::as_u64)
        .map(Duration::from_nanos);
    if uri.is_none() && interval.is_none() {
        return Ok(None);
    }
    let mut check = HealthCheck::default();
    if let Some(uri) = uri {
        check.uri = uri.to_string();
    }
    if let Some(interval) = interval {
        check.interval = interval;
    }
    if let Some(timeout) = object.get("health_timeout").and_then(Value::as_u64) {
        check.timeout = Duration::from_nanos(timeout);
    }
    if let Some(status) = object.get("health_status").and_then(Value::as_u64) {
        check.expected_status =
            Some(u16::try_from(status).map_err(|_| {
                invalid(&format!("{path}.health_status"), "status must fit in u16")
            })?);
    }
    if let Some(method) = object.get("health_method").and_then(Value::as_str) {
        check.method = method.parse().map_err(|error| {
            invalid(
                &format!("{path}.health_method"),
                format!("invalid method: {error}"),
            )
        })?;
    }
    Ok(Some(Arc::new(check)))
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
    use bytes::Bytes;
    use caddy_rs_http::Request;
    use http::Method;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    async fn spawn_echo_upstream() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(
                        |request: hyper::Request<hyper::body::Incoming>| async move {
                            let path = request.uri().path().to_string();
                            let proto = request
                                .headers()
                                .get("x-forwarded-proto")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("missing")
                                .to_string();
                            let host = request
                                .headers()
                                .get(http::header::HOST)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("missing")
                                .to_string();
                            let body = format!("path={path};proto={proto};host={host}");
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-upstream", "echo")
                                    .header("set-cookie", "a=1")
                                    .header("set-cookie", "b=2")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
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
        .unwrap()
    }

    #[tokio::test]
    async fn forwards_request_and_rewrites_headers() {
        let dial = spawn_echo_upstream().await;
        let handler = handler(&dial);
        let mut request = Request::new(Method::GET, "/hello?x=1".parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected proxied response");
        };
        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(body.contains("path=/hello"), "{body}");
        assert!(body.contains("proto=http"), "{body}");
        assert!(body.contains(&format!("host={dial}")), "{body}");
        assert_eq!(response.headers["x-proxy"], "caddy-rs");
        assert_eq!(response.headers["x-upstream"], "echo");
        assert_eq!(
            response.headers.get_all("set-cookie").iter().count(),
            2,
            "multi-value headers preserved"
        );
    }

    #[tokio::test]
    async fn unreachable_upstream_returns_502() {
        // Reserve a port by binding then dropping; the port is almost certainly closed afterwards.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let handler = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "load_balancing": {"retries": 1, "try_interval": 1_000_000}
            }),
            "handler",
        )
        .unwrap();
        let request = Request::new(Method::GET, "/".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
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

    #[test]
    fn rejects_tls_upstream_transport() {
        let error = ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8443"}],
                "transport": {"protocol": "http", "tls": {}}
            }),
            "handler",
        )
        .err()
        .expect("TLS upstream must be rejected");
        assert!(error.to_string().contains("TLS upstreams"));
    }
}
