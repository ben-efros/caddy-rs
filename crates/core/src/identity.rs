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
//! a located error. This is registered as divergence DIV-0036's sibling extension surface.

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
    /// any other non-empty string, which is used verbatim as a custom identity.
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
            _ => Ok(Self::Custom(trimmed.to_string())),
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
        match extra.get("server_identity") {
            None => Ok(Self::Default),
            Some(value) => Self::from_config_value(
                value,
                &format!("apps.http.servers.{server_name}.server_identity"),
            ),
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
}
