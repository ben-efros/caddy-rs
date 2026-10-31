//! Conversion between hyper messages and the transport-agnostic HTTP engine types.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

use caddy_rs_http::{Request, Response, Router};

/// Serve one hyper request through a router.
pub async fn serve_request(
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
) -> hyper::Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            eprintln!("caddy-rs: cannot read request body: {error}");
            return error_response(http::StatusCode::BAD_REQUEST, "400 Bad Request");
        }
    };
    let mut internal = Request::new(parts.method, parts.uri);
    internal.headers = parts.headers;
    internal.body = body;
    internal.remote_addr = remote_addr;
    internal.tls = tls;

    match router.handle(internal).await {
        Ok(response) => to_hyper(response),
        Err(error) => {
            eprintln!("caddy-rs: handler error: {error}");
            error_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "500 Internal Server Error",
            )
        }
    }
}

/// Convert an internal response to a hyper response.
pub fn to_hyper(response: Response) -> hyper::Response<Full<Bytes>> {
    let mut builder = hyper::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(response.body))
        .unwrap_or_else(|error| {
            eprintln!("caddy-rs: cannot build response: {error}");
            error_response(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "500 Internal Server Error",
            )
        })
}

fn error_response(status: http::StatusCode, body: &'static str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static error response is valid")
}

/// Type used for `service_fn` closures.
pub type ServiceResult = Result<hyper::Response<Full<Bytes>>, Infallible>;
