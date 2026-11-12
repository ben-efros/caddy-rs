//! Server identity (caddy-rs extension, T-CONF-060).
//!
//! Caddy v2.11.9 always identifies itself as `Caddy` in the HTTP `Server` response header and as
//! `Caddy/2.11.9` in the FastCGI `SERVER_SOFTWARE` parameter. caddy-rs must not silently claim to
//! be Caddy, so the identity is configurable with five modes:
//!
//! * `default` (also the behaviour when the field is absent): `caddy-rs/<build version>` on both
//!   surfaces;
//! * `name-only`: `Caddy` on both surfaces;
//! * `compatible`: exactly what Caddy v2.11.9 emits — `Caddy` header, `Caddy/2.11.9` FastCGI;
//! * a custom string: the operator string on both surfaces;
//! * `none`: no `Server` header and no `SERVER_SOFTWARE` parameter.
//!
//! The Caddyfile form is `servers { server_identity <mode> }` (see
//! [`crate::ServerIdentity::parse`] for the accepted spellings); the JSON config form is
//! `apps.http.servers.<name>.server_identity: "<mode-or-custom-string>"`. Both are validated with
//! a located error. The extension surface is registered as `DIV-0125` in the program compatibility
//! contract and the custom-value domain / pre-routing parity as `DIV-0126`.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{Error, Result};

/// The Caddy release whose identity `compatible` mode reproduces (`Caddy/2.11.9`).
pub const CADDY_COMPAT_VERSION: &str = "2.11.9";

/// The configured server identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ServerIdentity {
    /// `caddy-rs/<build version>` on both surfaces (the default when unconfigured).
    #[default]
    Default,
    /// The product name without a version: `Caddy`.
    NameOnly,
    /// Exactly what Caddy v2.11.9 emits: `Caddy` header, `Caddy/2.11.9` FastCGI parameter.
    Compatible,
    /// An operator-supplied identity string.
    Custom(String),
    /// No identification is emitted at all.
    None,
}

impl ServerIdentity {
    /// Parse the JSON config value (`apps.http.servers.<name>.server_identity`).
    ///
    /// Accepted values are the mode keywords `default`, `name-only`, `compatible` and `none`, or
    /// any other non-empty string of visible ASCII, which is used verbatim as a custom identity.
    ///
    /// A custom value must be usable as an HTTP header value: only U+0020..=U+007E (space through
    /// `~`) is accepted, so control characters, tabs and non-ASCII are a located error naming the
    /// mode and the offending character instead of being silently dropped by the header writer
    /// (DIV-0126). Non-ASCII is rejected rather than percent-encoded: the identity is an opaque
    /// operator string, and re-encoding it would emit something the operator did not configure
    /// (Caddy never encodes it either — Go's header writer refuses such values), so a located
    /// configuration error is the honest outcome.
    pub fn parse(text: &str) -> std::result::Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err("`server_identity` must not be empty".to_string());
        }
        match trimmed {
            "default" => Ok(Self::Default),
            "name-only" => Ok(Self::NameOnly),
            "compatible" => Ok(Self::Compatible),
            "none" => Ok(Self::None),
            _ => {
                validate_custom_identity(trimmed)?;
                Ok(Self::Custom(trimmed.to_string()))
            }
        }
    }

    /// Parse one config value, producing a located error for a non-string or empty value.
    pub fn from_config_value(value: &Value, path: &str) -> Result<Self> {
        let Some(text) = value.as_str() else {
            return Err(Error::invalid(
                path,
                format!("`server_identity` must be a string, got {value}"),
            ));
        };
        Self::parse(text).map_err(|message| Error::invalid(path, message))
    }

    /// Read the identity from one HTTP server's preserved extension fields.
    ///
    /// Absent means [`ServerIdentity::Default`]. A malformed value is a located error at
    /// `apps.http.servers.<name>.server_identity`.
    pub fn from_server_extra(server_name: &str, extra: &BTreeMap<String, Value>) -> Result<Self> {
        Ok(Self::from_server_extra_opt(server_name, extra)?.unwrap_or_default())
    }

    /// Read the identity, distinguishing "absent" (`None`) from an explicit
    /// `server_identity default` (`Some(Default)`).
    ///
    /// ADR-0010 §3 needs that distinction: absent resolves through the `stock_compat` and
    /// reverse-proxy matrix, while an explicit value always wins.
    pub fn from_server_extra_opt(
        server_name: &str,
        extra: &BTreeMap<String, Value>,
    ) -> Result<Option<Self>> {
        match extra.get("server_identity") {
            None => Ok(None),
            Some(value) => Self::from_config_value(
                value,
                &format!("apps.http.servers.{server_name}.server_identity"),
            )
            .map(Some),
        }
    }

    /// The HTTP `Server` response header value, or `None` when identification is disabled.
    pub fn http_header_value(&self) -> Option<String> {
        match self {
            Self::Default => Some(format!("caddy-rs/{}", crate::VERSION)),
            Self::NameOnly | Self::Compatible => Some("Caddy".to_string()),
            Self::Custom(identity) => Some(identity.clone()),
            Self::None => None,
        }
    }

    /// The FastCGI `SERVER_SOFTWARE` value, or `None` when identification is disabled.
    pub fn fastcgi_server_software(&self) -> Option<String> {
        match self {
            Self::Default => Some(format!("caddy-rs/{}", crate::VERSION)),
            Self::NameOnly => Some("Caddy".to_string()),
            Self::Compatible => Some(format!("Caddy/{CADDY_COMPAT_VERSION}")),
            Self::Custom(identity) => Some(identity.clone()),
            Self::None => None,
        }
    }
}

/// The effective identity for one HTTP server after applying the ADR-0010 §3 matrix.
///
/// The two surfaces resolve differently in secure-by-default reverse-proxy mode: the HTTP `Server`
/// header is suppressed while FastCGI `SERVER_SOFTWARE` keeps `caddy-rs/<version>`, which no single
/// [`ServerIdentity`] variant can express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The HTTP `Server` response header value, or `None` when the header must not be emitted.
    pub http_server_header: Option<String>,
    /// The FastCGI `SERVER_SOFTWARE` parameter value, or `None` when it must not be emitted.
    pub fastcgi_server_software: Option<String>,
}

impl Default for ResolvedIdentity {
    fn default() -> Self {
        Self::from_configured(ServerIdentity::Default)
    }
}

impl ResolvedIdentity {
    /// Resolve an explicitly configured identity, where both surfaces follow the mode.
    pub fn from_configured(identity: ServerIdentity) -> Self {
        Self {
            http_server_header: identity.http_header_value(),
            fastcgi_server_software: identity.fastcgi_server_software(),
        }
    }

    /// Resolve the effective identity from the configured value and the generation's context
    /// (ADR-0010 §3, `DIV-0132`).
    ///
    /// * an explicit `server_identity` always wins (including explicit `default`, which
    ///   re-enables `caddy-rs/<version>`);
    /// * absent + `stock_compat true` resolves to stock Caddy: `Caddy` / `Caddy/2.11.9`;
    /// * absent + secure-by-default + a `reverse_proxy` handler in the configuration suppresses the
    ///   HTTP `Server` header but keeps FastCGI `SERVER_SOFTWARE` at `caddy-rs/<version>` (it is an
    ///   upstream-visible parameter, not a browser fingerprint);
    /// * absent + secure-by-default without any `reverse_proxy` handler keeps `caddy-rs/<version>`
    ///   on both surfaces.
    pub fn resolve(
        configured: Option<ServerIdentity>,
        stock_compat: bool,
        has_reverse_proxy: bool,
    ) -> Self {
        match configured {
            Some(explicit) => Self::from_configured(explicit),
            None if stock_compat => Self::from_configured(ServerIdentity::Compatible),
            None if has_reverse_proxy => Self {
                http_server_header: None,
                fastcgi_server_software: Some(format!("caddy-rs/{}", crate::VERSION)),
            },
            None => Self::from_configured(ServerIdentity::Default),
        }
    }
}

/// Reject custom identity values that cannot be written into an HTTP header value.
///
/// The accepted set is exactly the visible ASCII range (U+0020..=U+007E): hyper's
/// `HeaderValue::from_str` refuses tab and every control character, and obs-text (U+0080..) is
/// transport-dependent (RFC 9110 deprecates it), so accepting either would reintroduce the silent
/// drop this check replaces.
fn validate_custom_identity(identity: &str) -> std::result::Result<(), String> {
    for (offset, character) in identity.char_indices() {
        if !matches!(character, ' '..='~') {
            return Err(format!(
                "`server_identity custom` value cannot be used as an HTTP `Server` header value: \
                 character U+{:04X} at byte {offset} is not visible ASCII; use only characters in \
                 U+0020..=U+007E",
                character as u32
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_render_both_surfaces() {
        assert_eq!(
            ServerIdentity::Default.http_header_value().as_deref(),
            Some(format!("caddy-rs/{}", crate::VERSION).as_str())
        );
        assert_eq!(
            ServerIdentity::Default.fastcgi_server_software().as_deref(),
            Some(format!("caddy-rs/{}", crate::VERSION).as_str())
        );
        assert_eq!(
            ServerIdentity::NameOnly.http_header_value().as_deref(),
            Some("Caddy")
        );
        assert_eq!(
            ServerIdentity::NameOnly
                .fastcgi_server_software()
                .as_deref(),
            Some("Caddy")
        );
        assert_eq!(
            ServerIdentity::Compatible.http_header_value().as_deref(),
            Some("Caddy")
        );
        assert_eq!(
            ServerIdentity::Compatible
                .fastcgi_server_software()
                .as_deref(),
            Some("Caddy/2.11.9")
        );
        assert_eq!(
            ServerIdentity::Custom("Acme/1".to_string())
                .http_header_value()
                .as_deref(),
            Some("Acme/1")
        );
        assert_eq!(
            ServerIdentity::Custom("Acme/1".to_string())
                .fastcgi_server_software()
                .as_deref(),
            Some("Acme/1")
        );
        assert_eq!(ServerIdentity::None.http_header_value(), None);
        assert_eq!(ServerIdentity::None.fastcgi_server_software(), None);
    }

    #[test]
    fn parsing_accepts_modes_and_custom_strings_but_rejects_empty() {
        assert_eq!(
            ServerIdentity::parse("default"),
            Ok(ServerIdentity::Default)
        );
        assert_eq!(
            ServerIdentity::parse("name-only"),
            Ok(ServerIdentity::NameOnly)
        );
        assert_eq!(
            ServerIdentity::parse("compatible"),
            Ok(ServerIdentity::Compatible)
        );
        assert_eq!(ServerIdentity::parse("none"), Ok(ServerIdentity::None));
        assert_eq!(
            ServerIdentity::parse("Acme Server/2"),
            Ok(ServerIdentity::Custom("Acme Server/2".to_string()))
        );
        assert!(ServerIdentity::parse("   ").is_err());
        assert!(ServerIdentity::parse("").is_err());
    }

    #[test]
    fn custom_identity_rejects_values_that_cannot_be_a_header_value() {
        // Control characters, DEL, an interior tab and non-ASCII are all rejected with a message
        // naming the mode and the offending code point (DIV-0126); the old code accepted them and
        // the header writer silently dropped the whole identity at runtime.
        for (value, code_point) in [
            ("Acme\u{0}Server", "U+0000"),
            ("Acme\u{7}Server", "U+0007"),
            ("Acme\u{7f}Server", "U+007F"),
            ("Acme\tServer", "U+0009"),
            ("Acme\u{e9}Server", "U+00E9"),
            ("\u{4e2d}\u{6587}", "U+4E2D"),
        ] {
            let error = ServerIdentity::parse(value).expect_err(&format!(
                "{value:?} must not be accepted as a custom identity"
            ));
            assert!(
                error.contains("`server_identity custom`"),
                "{value:?} error must name the mode, got {error}"
            );
            assert!(
                error.contains(code_point),
                "{value:?} error must name {code_point}, got {error}"
            );
            assert!(
                error.contains("HTTP `Server` header"),
                "{value:?} error must say what the value is for, got {error}"
            );
        }
        // Visible ASCII (including the space the routed-response test uses) still parses verbatim.
        assert_eq!(
            ServerIdentity::parse(" Acme Server/2 "),
            Ok(ServerIdentity::Custom("Acme Server/2".to_string()))
        );
        assert_eq!(
            ServerIdentity::parse("Acme!Server~2"),
            Ok(ServerIdentity::Custom("Acme!Server~2".to_string()))
        );
    }

    #[test]
    fn custom_identity_is_validated_at_config_load_with_a_located_error() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "server_identity".to_string(),
            Value::from("Acme\u{1}Server"),
        );
        let error = ServerIdentity::from_server_extra("srv0", &extra).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.server_identity"),
            "located error, got {message}"
        );
        assert!(
            message.contains("U+0001"),
            "error must name the offending character, got {message}"
        );
    }

    #[test]
    fn server_extra_absent_is_default_and_malformed_is_located() {
        let empty = BTreeMap::new();
        assert_eq!(
            ServerIdentity::from_server_extra("srv0", &empty).unwrap(),
            ServerIdentity::Default
        );
        let mut extra = BTreeMap::new();
        extra.insert("server_identity".to_string(), Value::from(42));
        let error = ServerIdentity::from_server_extra("srv0", &extra).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("apps.http.servers.srv0.server_identity"),
            "located error, got {error}"
        );
    }

    #[test]
    fn resolved_identity_follows_the_adr_0010_matrix() {
        // ADR-0010 §3 / DIV-0132: absent `server_identity` resolves through `stock_compat` and the
        // config-wide reverse-proxy detection; an explicit value always wins.
        let native = format!("caddy-rs/{}", crate::VERSION);
        let default = ResolvedIdentity::resolve(None, false, false);
        assert_eq!(default.http_server_header.as_deref(), Some(native.as_str()));
        assert_eq!(
            default.fastcgi_server_software.as_deref(),
            Some(native.as_str())
        );

        // Reverse-proxy deployment in secure-by-default mode: no HTTP `Server` header, but the
        // upstream-visible FastCGI parameter keeps the build identity.
        let proxied = ResolvedIdentity::resolve(None, false, true);
        assert_eq!(proxied.http_server_header, None);
        assert_eq!(
            proxied.fastcgi_server_software.as_deref(),
            Some(native.as_str())
        );

        // `stock_compat true` is stock Caddy on both surfaces.
        let stock = ResolvedIdentity::resolve(None, true, true);
        assert_eq!(stock.http_server_header.as_deref(), Some("Caddy"));
        assert_eq!(
            stock.fastcgi_server_software.as_deref(),
            Some("Caddy/2.11.9")
        );

        // An explicit identity always wins, including explicit `default`.
        for (configured, http, fastcgi) in [
            (
                ServerIdentity::Default,
                Some(format!("caddy-rs/{}", crate::VERSION)),
                Some(format!("caddy-rs/{}", crate::VERSION)),
            ),
            (
                ServerIdentity::NameOnly,
                Some("Caddy".to_string()),
                Some("Caddy".to_string()),
            ),
            (
                ServerIdentity::Compatible,
                Some("Caddy".to_string()),
                Some("Caddy/2.11.9".to_string()),
            ),
            (
                ServerIdentity::Custom("Acme/1".to_string()),
                Some("Acme/1".to_string()),
                Some("Acme/1".to_string()),
            ),
            (ServerIdentity::None, None, None),
        ] {
            let resolved = ResolvedIdentity::resolve(Some(configured.clone()), false, true);
            assert_eq!(
                resolved.http_server_header, http,
                "HTTP surface for {configured:?}"
            );
            assert_eq!(
                resolved.fastcgi_server_software, fastcgi,
                "FastCGI surface for {configured:?}"
            );
        }
    }

    #[test]
    fn absent_and_explicit_default_are_distinguishable() {
        let empty = BTreeMap::new();
        assert_eq!(
            ServerIdentity::from_server_extra_opt("srv0", &empty).unwrap(),
            None
        );
        let mut extra = BTreeMap::new();
        extra.insert("server_identity".to_string(), Value::from("default"));
        assert_eq!(
            ServerIdentity::from_server_extra_opt("srv0", &extra).unwrap(),
            Some(ServerIdentity::Default)
        );
    }
}
