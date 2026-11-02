//! Automatic-HTTPS request handling shared by HTTP listeners: ACME HTTP-01 challenge responses
//! and HTTP→HTTPS redirects.
//!
//! The request interception lives at the connection boundary (before the router), matching the
//! order Caddy applies automatic HTTPS:
//!
//! 1. `/.well-known/acme-challenge/<token>` is answered from the shared
//!    [`Http01TokenStore`](caddy_rs_tls::Http01TokenStore), even while an order is being
//!    validated;
//! 2. any other request whose `Host` belongs to an automatic-HTTPS site is redirected to
//!    `https://<host><path?query>` with `308 Permanent Redirect` (unless `disable_redirects`);
//! 3. everything else reaches the configured routes.

use std::sync::Arc;

use bytes::Bytes;

use caddy_rs_http::Body;
use caddy_rs_tls::{
    AutomaticHttpsPlan, CertificateResolver, Http01TokenStore, TlsAlpn01TokenStore,
    HTTP01_PATH_PREFIX,
};

/// Redirect policy for one generation's HTTP listeners.
#[derive(Debug, Clone)]
pub(crate) struct RedirectPolicy {
    /// Hosts that should be redirected to HTTPS (lowercase, no ports).
    pub(crate) hosts: Vec<String>,
    /// Whether every Host should be redirected (a hostless HTTPS site exists).
    pub(crate) redirect_all: bool,
    /// Effective HTTPS port; omitted from the `Location` when 443.
    pub(crate) https_port: u16,
}

impl RedirectPolicy {
    fn redirects_host(&self, host: &str) -> bool {
        if self.redirect_all {
            return true;
        }
        let host = normalize_host(host);
        self.hosts.iter().any(|candidate| candidate == &host)
    }

    fn location(&self, host: &str, path_and_query: &str) -> String {
        let host = normalize_host(host);
        if self.https_port == 443 {
            format!("https://{host}{path_and_query}")
        } else {
            format!("https://{host}:{}{path_and_query}", self.https_port)
        }
    }
}

/// Everything the supervisor prepared for one generation's automatic HTTPS: the certificate
/// resolver for TLS listeners, the policy plan, and the pre-routing state for HTTP listeners.
#[derive(Debug, Clone)]
pub(crate) struct PreparedAutomaticHttps {
    /// Resolver containing manual plus automatically obtained certificates.
    pub(crate) resolver: Arc<CertificateResolver>,
    /// Derived plan (subjects, ports, redirects).
    pub(crate) plan: AutomaticHttpsPlan,
    /// Pre-routing state for cleartext listeners.
    pub(crate) serving: Arc<AutomaticHttpsServing>,
    /// TLS-ALPN-01 challenge-certificate store shared with the issuer that ran this apply. TLS
    /// listeners wrap their resolver with it so `acme-tls/1` handshakes are answered.
    pub(crate) tls_alpn01_tokens: Arc<TlsAlpn01TokenStore>,
}

/// Per-generation automatic-HTTPS serving state for cleartext listeners.
#[derive(Debug, Clone)]
pub(crate) struct AutomaticHttpsServing {
    /// HTTP-01 tokens registered by the issuer currently running (empty between orders).
    pub(crate) tokens: Arc<Http01TokenStore>,
    /// Redirect behaviour, when HTTP→HTTPS redirects are enabled.
    pub(crate) redirect: Option<RedirectPolicy>,
}

impl AutomaticHttpsServing {
    /// Answer challenge requests and redirects before the router sees the request.
    pub(crate) fn pre_router_response(
        &self,
        request: &hyper::Request<hyper::body::Incoming>,
    ) -> Option<hyper::Response<Body>> {
        let path = request.uri().path();
        if let Some(token) = path.strip_prefix(HTTP01_PATH_PREFIX) {
            let token = token.trim_end_matches('/');
            return Some(match self.tokens.key_authorization(token) {
                Some(key_authorization) => text_response(200, &key_authorization),
                None => text_response(404, "404 Not Found"),
            });
        }
        let redirect = self.redirect.as_ref()?;
        if request.method() == hyper::Method::CONNECT {
            return None;
        }
        let host = request
            .headers()
            .get(hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.to_string())
            })?;
        if !redirect.redirects_host(&host) {
            return None;
        }
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let location = redirect.location(&host, path_and_query);
        Some(
            hyper::Response::builder()
                .status(308)
                .header(hyper::header::LOCATION, location)
                .header(hyper::header::CONTENT_LENGTH, "0")
                .body(Body::from_bytes(Bytes::new()))
                .expect("static redirect response is valid"),
        )
    }
}

fn text_response(status: u16, body: &str) -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from_bytes(Bytes::from(body.to_string())))
        .expect("static response is valid")
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}
