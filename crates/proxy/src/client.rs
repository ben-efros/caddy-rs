//! Shared outbound HTTP client for proxying and health checks.

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Hyper client body type used for outbound requests.
pub type ClientBody = Full<Bytes>;

/// The outbound client type.
pub type HttpClient = Client<HttpConnector, ClientBody>;

/// Build the client used by the reverse proxy and active health checks.
pub fn build_client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build_http()
}
