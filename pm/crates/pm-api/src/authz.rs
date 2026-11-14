//! Request guards for the mutating management routes and the API's loopback origin.
//!
//! Session endpoints (`/auth/*`) hand out bearer tokens; [`require_mutation_auth`] then requires one
//! on every mutation that changes configuration or users. The loopback peer guard inside each
//! handler stays in place as defense in depth: authentication does not replace "the management port
//! is local", it adds a second, independent condition.
//!
//! # Fail-closed
//!
//! The gate is unconditional: it never consults the user store to decide whether authentication is
//! needed. The only unauthenticated way to create a credential is `POST /auth/setup`, which is
//! loopback-only and refuses a second administrator. A process-local, in-memory user store that is
//! empty after a restart therefore cannot turn into an open API: mutations answer `401` until an
//! administrator is created again (or supplied through the bootstrap environment variables).
//!
//! # Default-deny mapping
//!
//! [`required_capability`] maps every mutating path to a capability and falls back to
//! [`Section::Settings`]/[`Action::Admin`] for a path it does not recognise, so adding a route
//! without updating this table cannot ship it unauthenticated. Add an explicit arm when a route
//! lands so its callers get the narrowest capability instead of the fallback.
//!
//! Reads are not gated here; they either expose only non-sensitive data or enforce their own
//! contract (`/users`). [`require_loopback_host`] separately rejects a non-loopback `Host` header on
//! every request, which blocks DNS-rebinding pages from reading those configuration routes through
//! the operator's browser.

use std::net::IpAddr;

use axum::{
    extract::{Request, State},
    http::{header, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use caddy_rs_authn::{Action, Section};

use crate::{users::require_capability, ApiError, ApiState};

/// The capability a mutating request needs, or `None` when this layer does not gate it.
///
/// Session routes are excluded: login and refresh are how a caller obtains a token, and logout and
/// `me` authenticate explicitly. Unknown mutating paths are *not* excluded; they get the strongest
/// capability so a new route cannot be unauthenticated by omission.
pub(crate) fn required_capability(method: &Method, path: &str) -> Option<(Section, Action)> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    // Exact allow-list, not a prefix: a future `/auth/password` or `/auth/totp` mutation must not
    // inherit an exemption just because it shares the namespace.
    if matches!(
        path,
        "/auth/setup" | "/auth/login" | "/auth/refresh" | "/auth/logout"
    ) {
        return None;
    }
    if path.starts_with("/users") {
        // The handlers also check; doing it here too means a future `/users/...` mutation cannot
        // skip the gate by forgetting its handler check. Both paths use `require_capability`, so
        // the status codes and messages are identical.
        return Some((Section::Users, mutating_action(method)?));
    }
    if path == "/config/apply" {
        return Some((Section::Settings, Action::Admin));
    }
    if path == "/security-headers" {
        return Some((Section::Settings, Action::Update));
    }

    let action = mutating_action(method)?;
    if path.starts_with("/hosts") {
        // enable/disable are POST but modify an existing host, so they need update, not create.
        if *method == Method::POST && (path.ends_with("/enable") || path.ends_with("/disable")) {
            return Some((Section::Hosts, Action::Update));
        }
        return Some((Section::Hosts, action));
    }
    if path.starts_with("/certificates") {
        return Some((Section::Certificates, action));
    }
    Some((Section::Settings, Action::Admin))
}

/// The capability implied by a mutating HTTP method; `None` for methods that are not mutating.
fn mutating_action(method: &Method) -> Option<Action> {
    match *method {
        Method::POST => Some(Action::Create),
        Method::PUT | Method::PATCH => Some(Action::Update),
        Method::DELETE => Some(Action::Delete),
        _ => None,
    }
}

/// Require a capability for every mutation.
///
/// A `401` from a missing, malformed, expired or epoch-stale token and a `403` from a valid token
/// without the capability are produced by the same helper the user routes use, so the two paths
/// cannot drift. Both carry the `WWW-Authenticate: Bearer` challenge that tells the UI to refresh.
pub(crate) async fn require_mutation_auth(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some((section, action)) = required_capability(request.method(), request.uri().path()) {
        // Test-only escape hatch; production always fails closed here.
        if !state.bootstrap_window {
            if let Err(error) = require_capability(&state, request.headers(), section, action).await
            {
                return error.into_response();
            }
        }
    }
    next.run(request).await
}

/// Reject a request whose `Host` header is not a loopback name.
///
/// The management API is same-origin with the embedded UI on a loopback listener. Without this
/// check a DNS-rebinding page could make the operator's browser send requests to `127.0.0.1` and
/// read the unauthenticated configuration routes; a browser always carries the attacker-controlled
/// name in `Host`, so refusing non-loopback names blocks that path.
pub(crate) async fn require_loopback_host(request: Request, next: Next) -> Response {
    match request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        Some(host) if host_is_loopback(host) => next.run(request).await,
        Some(_) => ApiError::Forbidden(
            "the management API only accepts loopback Host headers; reach it as localhost or 127.0.0.1"
                .to_owned(),
        )
        .into_response(),
        None => ApiError::Forbidden(
            "the management API requires a loopback Host header".to_owned(),
        )
        .into_response(),
    }
}

/// Whether a `Host` header names the local machine (`localhost`, a loopback IP, or one with a
/// port). A bare IPv6 literal is accepted when it parses as loopback; RFC 9110 requires brackets in
/// a `Host` header, and the bracketed form is handled first.
fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        let Some((name, suffix)) = rest.split_once(']') else {
            return false;
        };
        // After `]` only an empty string or `:port` is legal; `[::1]evil.example.com` is not.
        if !suffix.is_empty() {
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            if port.is_empty() || port.parse::<u16>().is_err() {
                return false;
            }
        }
        name
    } else if host.matches(':').count() == 1 {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    } else {
        host
    };
    // A trailing dot is the fully-qualified spelling of the same name.
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    hostname.eq_ignore_ascii_case("localhost")
        || hostname
            .parse::<IpAddr>()
            .map(|address| match address {
                IpAddr::V4(v4) => v4.is_loopback(),
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.to_ipv4_mapped()
                            .is_some_and(|mapped| mapped.is_loopback())
                }
            })
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_session_routes_are_never_gated() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(required_capability(&method, "/hosts"), None);
        }
        assert_eq!(
            required_capability(&Method::POST, "/auth/login"),
            None,
            "login must be reachable without a token"
        );
        assert_eq!(
            required_capability(&Method::POST, "/auth/refresh"),
            None
        );
        assert_eq!(
            required_capability(&Method::POST, "/auth/password"),
            Some((Section::Settings, Action::Admin)),
            "only the four session routes are exempt; a future /auth mutation is gated"
        );
    }

    #[test]
    fn host_mutations_map_to_the_hosts_section() {
        assert_eq!(
            required_capability(&Method::POST, "/hosts"),
            Some((Section::Hosts, Action::Create))
        );
        assert_eq!(
            required_capability(&Method::PUT, "/hosts/abc"),
            Some((Section::Hosts, Action::Update))
        );
        assert_eq!(
            required_capability(&Method::PATCH, "/hosts/abc"),
            Some((Section::Hosts, Action::Update))
        );
        assert_eq!(
            required_capability(&Method::DELETE, "/hosts/abc"),
            Some((Section::Hosts, Action::Delete))
        );
        assert_eq!(
            required_capability(&Method::POST, "/hosts/abc/enable"),
            Some((Section::Hosts, Action::Update)),
            "toggling an existing host is an update, not a create"
        );
        assert_eq!(
            required_capability(&Method::POST, "/hosts/abc/disable"),
            Some((Section::Hosts, Action::Update))
        );
        assert_eq!(
            required_capability(&Method::PUT, "/hosts/abc/security-headers"),
            Some((Section::Hosts, Action::Update))
        );
    }

    #[test]
    fn other_mutations_map_to_their_owning_section() {
        assert_eq!(
            required_capability(&Method::POST, "/certificates/intent"),
            Some((Section::Certificates, Action::Create))
        );
        assert_eq!(
            required_capability(&Method::POST, "/certificates/custom"),
            Some((Section::Certificates, Action::Create))
        );
        assert_eq!(
            required_capability(&Method::DELETE, "/certificates/custom/abc"),
            Some((Section::Certificates, Action::Delete))
        );
        assert_eq!(
            required_capability(&Method::PUT, "/security-headers"),
            Some((Section::Settings, Action::Update))
        );
        assert_eq!(
            required_capability(&Method::POST, "/config/apply"),
            Some((Section::Settings, Action::Admin)),
            "applying a compiled config is an administrative action"
        );
    }

    #[test]
    fn user_mutations_are_gated_by_the_layer_too() {
        assert_eq!(
            required_capability(&Method::POST, "/users"),
            Some((Section::Users, Action::Create))
        );
        assert_eq!(
            required_capability(&Method::PATCH, "/users/abc"),
            Some((Section::Users, Action::Update))
        );
        assert_eq!(
            required_capability(&Method::DELETE, "/users/abc"),
            Some((Section::Users, Action::Delete))
        );
    }

    #[test]
    fn unknown_mutations_fail_closed_to_the_strongest_capability() {
        assert_eq!(
            required_capability(&Method::POST, "/nope"),
            Some((Section::Settings, Action::Admin))
        );
        assert_eq!(
            required_capability(&Method::POST, "/config"),
            Some((Section::Settings, Action::Admin))
        );
    }

    #[test]
    fn loopback_hosts_are_accepted_and_everything_else_is_not() {
        for host in [
            "localhost",
            "localhost:81",
            "LOCALHOST:81",
            "localhost.",
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:81",
            "[::ffff:127.0.0.1]:81",
            "::1",
        ] {
            assert!(host_is_loopback(host), "{host} must be accepted");
        }
        for host in [
            "evil.example.com",
            "evil.example.com:81",
            "10.0.0.1:81",
            "[fe80::1]:81",
            "127.0.0.1.evil.example.com",
            "[::1",
            "[::1]evil.example.com",
            "[::1]:not-a-port",
        ] {
            assert!(!host_is_loopback(host), "{host} must be refused");
        }
    }
}
