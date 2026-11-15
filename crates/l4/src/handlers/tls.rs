//! TLS termination at the L4 layer (T-L4-008, ADR-030).
//!
//! The `tls` stage terminates TLS on a raw TCP connection, replacing the connection's stream with
//! the decrypted one. The certificate is chosen by SNI through the same
//! [`caddy_rs_tls::CertificateResolver`] the HTTP listener uses, so an L4 route and an HTTP server
//! on the same host present the same certificate, and client-certificate policy comes from the same
//! [`caddy_rs_tls::TlsServerOptions`] the HTTP listener builds its configuration from.
//!
//! Two ADR-030 requirements shape this module:
//!
//! - **PROXY before terminated upstream (Q2).** Termination does not consume the pipeline: the
//!   decrypted stream replaces the raw one and the *next* stage (typically `proxy_protocol`) runs
//!   against it. The addresses that stage reports are captured **before** the handshake, from the
//!   raw socket, so a terminated connection still forwards the real client's address.
//! - **Handler ordering.** [`validate_stage_order`] rejects a pipeline that would inject a PROXY
//!   header after the bytes it must precede, or terminate TLS after proxying started.

use std::sync::Arc;

use caddy_rs_tls::{TlsResolver, TlsServerOptions};
use tokio_rustls::TlsAcceptor;

/// A TLS stage that cannot serve a connection.
#[derive(Debug)]
pub enum TerminateError {
    /// The server configuration could not be built from the resolver/options pair.
    Config(String),
    /// The handshake failed (bad ClientHello, no certificate for the SNI, client-auth failure).
    Handshake(String),
}

impl std::fmt::Display for TerminateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => write!(f, "l4 tls configuration error: {message}"),
            Self::Handshake(message) => write!(f, "l4 tls handshake failed: {message}"),
        }
    }
}

impl std::error::Error for TerminateError {}

/// A validated TLS termination stage.
#[derive(Clone)]
pub struct TlsTerminator {
    acceptor: TlsAcceptor,
    options: TlsServerOptions,
}

impl std::fmt::Debug for TlsTerminator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTerminator")
            .field("alpn", &self.options.alpn.len())
            .field("client_auth", &self.options.client_auth)
            .finish()
    }
}

impl TlsTerminator {
    /// Builds a terminator whose certificate comes from `resolver` under `options`.
    ///
    /// Both come from the shared caddy-rs TLS layer, so mTLS modes, versions, curves and ALPN are
    /// the HTTP listener's own policy rather than a second, divergent implementation.
    pub fn new(
        resolver: Arc<dyn TlsResolver>,
        options: &TlsServerOptions,
    ) -> Result<Self, TerminateError> {
        let config = caddy_rs_tls::build_server_config_with_cert_resolver(resolver, options)
            .map_err(|error| TerminateError::Config(error.to_string()))?;
        Ok(Self {
            acceptor: TlsAcceptor::from(config),
            options: options.clone(),
        })
    }

    /// The ALPN protocols the stage will negotiate, in preference order.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        self.options.alpn.clone()
    }

    /// Terminates TLS over `stream`, returning the decrypted stream and the negotiated ALPN.
    pub async fn terminate<S>(
        &self,
        stream: S,
    ) -> Result<(tokio_rustls::server::TlsStream<S>, Option<Vec<u8>>), TerminateError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|error| TerminateError::Handshake(error.to_string()))?;
        let alpn = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(std::borrow::ToOwned::to_owned);
        Ok((stream, alpn))
    }
}

/// The stage names the L4 pipeline supports, in the order they may appear.
pub const STAGE_ORDER: &[&str] = &["tls", "throttle", "proxy_protocol", "proxy"];

/// An invalid handler order for a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageOrderError {
    message: String,
}

impl StageOrderError {
    /// The reason, naming the offending stages.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for StageOrderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StageOrderError {}

/// Validates a route's handler order.
///
/// The rules are the ones ADR-030 makes observable:
///
/// - `tls` must precede `proxy_protocol` and `proxy` (you cannot inject a header into, or proxy,
///   a stream you have not yet decrypted);
/// - `proxy_protocol` must precede `proxy` (the header must be the first bytes the upstream sees);
/// - `proxy` is terminal (nothing may follow it);
/// - no stage may repeat;
/// - every name must be a known stage.
pub fn validate_stage_order(stages: &[&str]) -> Result<(), StageOrderError> {
    let mut seen: Vec<&str> = Vec::with_capacity(stages.len());
    for (index, stage) in stages.iter().copied().enumerate() {
        let Some(position) = STAGE_ORDER.iter().position(|known| *known == stage) else {
            return Err(StageOrderError {
                message: format!(
                    "unknown l4 handler {stage:?} at position {index}; expected one of {}",
                    STAGE_ORDER.join(", ")
                ),
            });
        };
        if seen.contains(&stage) {
            return Err(StageOrderError {
                message: format!("l4 handler {stage:?} appears more than once"),
            });
        }
        // Each stage's position in the canonical order must be greater than the previous one's,
        // except that `throttle` may appear anywhere before `proxy`.
        if let Some(previous) = seen
            .last()
            .and_then(|last| STAGE_ORDER.iter().position(|k| k == last))
        {
            let out_of_order = position <= previous;
            let throttle_exempt = stage == "throttle" || seen.last() == Some(&"throttle");
            if out_of_order && !throttle_exempt {
                return Err(StageOrderError {
                    message: format!(
                        "l4 handler {stage:?} must not follow {}; the order is {}",
                        seen.last().copied().unwrap_or(""),
                        STAGE_ORDER.join(" -> ")
                    ),
                });
            }
        }
        if stage == "proxy" && index + 1 != stages.len() {
            return Err(StageOrderError {
                message: format!(
                    "l4 handler \"proxy\" is terminal but is followed by {:?}",
                    stages[index + 1]
                ),
            });
        }
        seen.push(stage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_orders_are_accepted() {
        validate_stage_order(&["tls", "proxy_protocol", "proxy"]).expect("terminated + PROXY");
        validate_stage_order(&["tls", "proxy"]).expect("terminated");
        validate_stage_order(&["proxy_protocol", "proxy"]).expect("passthrough + PROXY");
        validate_stage_order(&["proxy"]).expect("plain proxy");
        validate_stage_order(&[]).expect("a route with no handlers");
        validate_stage_order(&["throttle", "proxy"]).expect("shaped proxy");
        validate_stage_order(&["tls", "throttle", "proxy_protocol", "proxy"])
            .expect("shaped terminated proxy");
    }

    #[test]
    fn proxy_protocol_after_proxy_is_rejected() {
        let error = validate_stage_order(&["proxy", "proxy_protocol"]).expect_err("rejected");
        assert!(error.message().contains("terminal"), "{}", error.message());
    }

    #[test]
    fn tls_after_proxy_protocol_is_rejected() {
        let error =
            validate_stage_order(&["proxy_protocol", "tls", "proxy"]).expect_err("rejected");
        assert!(
            error.message().contains("must not follow"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_repeated_stage_is_rejected() {
        let error = validate_stage_order(&["tls", "tls", "proxy"]).expect_err("rejected");
        assert!(error.message().contains("more than once"));
    }

    #[test]
    fn an_unknown_stage_is_rejected_by_name() {
        let error = validate_stage_order(&["tls", "dns", "proxy"]).expect_err("rejected");
        assert!(error.message().contains("\"dns\""));
        assert!(error.message().contains("expected one of"));
    }

    #[test]
    fn nothing_may_follow_the_proxy_stage() {
        let error = validate_stage_order(&["proxy", "tls"]).expect_err("rejected");
        assert!(error.message().contains("terminal"));
    }
}
