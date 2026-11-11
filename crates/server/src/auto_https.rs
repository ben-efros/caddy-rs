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

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;

use caddy_rs_http::Body;
use caddy_rs_tls::{
    AutomaticHttpsPlan, AutomaticHttpsRenewals, CertificateResolver, Http01TokenStore,
    TlsAlpn01TokenStore, HTTP01_PATH_PREFIX,
};

/// Redirect policy for one generation's HTTP listeners.
#[derive(Debug, Clone)]
pub(crate) struct RedirectPolicy {
    /// Hosts that should be redirected to HTTPS (lowercase, no ports).
    pub(crate) hosts: Vec<String>,
    /// Whether every Host should be redirected (a hostless HTTPS site exists).
    pub(crate) redirect_all: bool,
    /// HTTPS destination port per host (implicit HTTPS on a non-standard port redirects to that
    /// same port); hosts absent from the map use [`Self::https_port`].
    pub(crate) host_ports: BTreeMap<String, u16>,
    /// Legacy/fallback HTTPS port for hosts without a per-host destination.
    pub(crate) https_port: u16,
    /// HTTPS destination for hostless/catch-all redirects.
    pub(crate) redirect_all_port: u16,
    /// Configured HTTP port (`apps.http.http_port`, default 80); a redirect destination on this
    /// port never needs an explicit port (Caddy `makeRedirRoute`).
    pub http_port: u16,
}

impl RedirectPolicy {
    fn redirects_host(&self, host: &str) -> bool {
        if self.redirect_all {
            return true;
        }
        let host = normalize_host(host);
        self.hosts.iter().any(|candidate| candidate == &host)
    }

    /// The `Location` for one redirect, following Caddy's `makeRedirRoute`.
    ///
    /// The destination port is omitted when it is the configured HTTP or HTTPS port (or 80/443):
    /// a site that moved to `https_port 18443` redirects to `https://host/path`, not
    /// `https://host:18443/path`, exactly like Caddy. Implicitly-HTTPS sites on a non-standard
    /// port keep the explicit port because the destination is neither configured port.
    fn location(&self, host: &str, path_and_query: &str) -> String {
        let host = normalize_host(host);
        let destination = self.host_ports.get(&host).copied().unwrap_or_else(|| {
            if self.redirect_all {
                self.redirect_all_port
            } else {
                self.https_port
            }
        });
        let mut location = format!("https://{host}");
        if destination != self.http_port
            && destination != self.https_port
            && destination != 80
            && destination != 443
        {
            location.push(':');
            location.push_str(&destination.to_string());
        }
        location.push_str(path_and_query);
        location
    }
}

/// Everything the supervisor prepared for one generation's automatic HTTPS: the certificate
/// resolver for TLS listeners, the policy plan, the pre-routing state for HTTP listeners and the
/// generation's renewal scheduler.
///
/// Not `Clone`: the renewal scheduler has generation-scoped ownership and must not be duplicated.
#[derive(Debug)]
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
    /// Generation-scoped certificate renewal scheduler returned by provisioning.
    ///
    /// The runtime owns this value for the generation's lifetime: keeping it alive keeps renewing
    /// certificates into the resolver above; dropping it (or stopping it) aborts the scheduler.
    pub(crate) renewals: Option<AutomaticHttpsRenewals>,
    /// Generation-scoped OCSP refresh scheduler (T-TLS-081).
    pub(crate) ocsp_refresh: Option<crate::runtime::OcspRefresh>,
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
        // `location` is built from the request host and target; `http` only accepts visible ASCII
        // in both, so this cannot fail today. Build the response fallibly anyway: a bad `Location`
        // must not panic the process, it just means this request is not redirected.
        let location = hyper::header::HeaderValue::from_str(&location).ok()?;
        let mut response = hyper::Response::new(Body::from_bytes(Bytes::new()));
        *response.status_mut() = hyper::StatusCode::PERMANENT_REDIRECT;
        response
            .headers_mut()
            .insert(hyper::header::LOCATION, location);
        response.headers_mut().insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from_static("0"),
        );
        Some(response)
    }
}

fn text_response(status: u16, body: &str) -> hyper::Response<Body> {
    // `status` is a literal owned by this module and `body` is a static string, so no input can
    // make this fail; build the response directly instead of through a fallible builder.
    let mut response = hyper::Response::new(Body::from_bytes(Bytes::from(body.to_string())));
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_response_falls_back_on_an_out_of_range_status() {
        // `StatusCode::from_u16(999)` is an error; this used to panic via `Response::builder()`
        // `.expect("static response is valid")`.
        let response = text_response(1000, "x");
        assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("text/plain; charset=utf-8"))
        );
    }

    #[test]
    fn text_response_keeps_the_requested_status_and_body() {
        let response = text_response(404, "404 Not Found");
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }
}
