//! Native request/response shapes for the proxy-host API.
//!
//! These types are deliberately separate from `pm-core`'s storage structs. Core serializes the
//! persisted schema (`ssl_forced`, `preserve_host`, ...); the public API is camelCase and rejects
//! unknown fields so an NPM-shaped payload (`forward_host`, `certificate_id`) fails loudly instead
//! of being silently ignored. A later `--compat npm` adapter translates NPM payloads into these
//! native types.

use caddy_rs_pm_core::{
    CertificateId, DeadSpec, Host, HostSpec, HostTls, PolicyId, ProxySpec, RedirectScheme,
    RedirectSpec, TlsMode, Upstream, UpstreamScheme,
};
use caddy_rs_pm_hosts::StoredHost;
use caddy_rs_pm_service::HostDraft;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_redirect_status() -> u16 {
    301
}

fn default_redirect_scheme() -> RedirectScheme {
    RedirectScheme::Auto
}

/// `POST /hosts` and `PUT /hosts/{id}` body.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostWriteRequest {
    pub domains: Vec<String>,
    #[serde(default)]
    pub tls: HostTlsDto,
    pub spec: HostSpecDto,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl HostWriteRequest {
    #[must_use]
    pub fn into_draft(self) -> HostDraft {
        HostDraft {
            domains: self.domains,
            tls: self.tls.into(),
            spec: self.spec.into(),
            enabled: self.enabled,
        }
    }
}

/// `PATCH /hosts/{id}` body. Every field is optional, but at least one must be present.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPatchRequest {
    #[serde(default)]
    pub domains: Option<Vec<String>>,
    #[serde(default)]
    pub tls: Option<HostTlsDto>,
    #[serde(default)]
    pub spec: Option<HostSpecDto>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl HostPatchRequest {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_none()
            && self.tls.is_none()
            && self.spec.is_none()
            && self.enabled.is_none()
    }

    /// Merge the patch into an existing host and return the resulting draft.
    #[must_use]
    pub fn apply_to(self, host: &Host) -> HostDraft {
        HostDraft {
            domains: self.domains.unwrap_or_else(|| host.domains.clone()),
            tls: self.tls.map_or_else(|| host.tls.clone(), HostTls::from),
            spec: self.spec.map_or_else(|| host.spec.clone(), HostSpec::from),
            enabled: self.enabled.unwrap_or(host.enabled),
        }
    }
}

/// TLS binding in the public schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTlsDto {
    pub mode: TlsMode,
    #[serde(default)]
    pub certificate_id: Option<CertificateId>,
    #[serde(default)]
    pub auto_policy_id: Option<PolicyId>,
    #[serde(default)]
    pub ssl_forced: bool,
    #[serde(default)]
    pub hsts_enabled: bool,
    #[serde(default)]
    pub hsts_subdomains: bool,
}

impl Default for HostTlsDto {
    fn default() -> Self {
        Self::from(&HostTls::disabled())
    }
}

impl From<HostTlsDto> for HostTls {
    fn from(dto: HostTlsDto) -> Self {
        Self {
            mode: dto.mode,
            certificate_id: dto.certificate_id,
            auto_policy_id: dto.auto_policy_id,
            ssl_forced: dto.ssl_forced,
            hsts_enabled: dto.hsts_enabled,
            hsts_subdomains: dto.hsts_subdomains,
        }
    }
}

impl From<&HostTls> for HostTlsDto {
    fn from(tls: &HostTls) -> Self {
        Self {
            mode: tls.mode,
            certificate_id: tls.certificate_id,
            auto_policy_id: tls.auto_policy_id,
            ssl_forced: tls.ssl_forced,
            hsts_enabled: tls.hsts_enabled,
            hsts_subdomains: tls.hsts_subdomains,
        }
    }
}

/// Reverse-proxy spec in the public schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxySpecDto {
    pub upstream: UpstreamDto,
    #[serde(default)]
    pub websocket: bool,
    #[serde(default = "default_true")]
    pub preserve_host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamDto {
    pub scheme: UpstreamScheme,
    pub host: String,
    pub port: u16,
}

/// Redirect spec in the public schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedirectSpecDto {
    #[serde(default = "default_redirect_scheme")]
    pub scheme: RedirectScheme,
    pub target: String,
    #[serde(default = "default_redirect_status")]
    pub status: u16,
    #[serde(default = "default_true")]
    pub preserve_path: bool,
}

/// Tagged host spec. The API emits `{"kind":"dead"}` for a dead host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "spec",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HostSpecDto {
    Proxy(ProxySpecDto),
    Redirect(RedirectSpecDto),
    Dead,
}

impl From<HostSpecDto> for HostSpec {
    fn from(dto: HostSpecDto) -> Self {
        match dto {
            HostSpecDto::Proxy(proxy) => Self::Proxy(ProxySpec {
                upstream: Upstream {
                    scheme: proxy.upstream.scheme,
                    host: proxy.upstream.host,
                    port: proxy.upstream.port,
                },
                websocket: proxy.websocket,
                preserve_host: proxy.preserve_host,
            }),
            HostSpecDto::Redirect(redirect) => Self::Redirect(RedirectSpec {
                scheme: redirect.scheme,
                target: redirect.target,
                status: redirect.status,
                preserve_path: redirect.preserve_path,
            }),
            HostSpecDto::Dead => Self::Dead(DeadSpec),
        }
    }
}

impl From<&HostSpec> for HostSpecDto {
    fn from(spec: &HostSpec) -> Self {
        match spec {
            HostSpec::Proxy(proxy) => Self::Proxy(ProxySpecDto {
                upstream: UpstreamDto {
                    scheme: proxy.upstream.scheme,
                    host: proxy.upstream.host.clone(),
                    port: proxy.upstream.port,
                },
                websocket: proxy.websocket,
                preserve_host: proxy.preserve_host,
            }),
            HostSpec::Redirect(redirect) => Self::Redirect(RedirectSpecDto {
                scheme: redirect.scheme,
                target: redirect.target.clone(),
                status: redirect.status,
                preserve_path: redirect.preserve_path,
            }),
            HostSpec::Dead(_) => Self::Dead,
        }
    }
}

/// Full host document returned by detail, create, update and toggle routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResponse {
    pub id: u64,
    pub domains: Vec<String>,
    pub tls: HostTlsDto,
    pub enabled: bool,
    pub spec: HostSpecDto,
    pub revision: u64,
}

impl From<&StoredHost> for HostResponse {
    fn from(stored: &StoredHost) -> Self {
        Self {
            id: stored.host.id.0,
            domains: stored.host.domains.clone(),
            tls: HostTlsDto::from(&stored.host.tls),
            enabled: stored.host.enabled,
            spec: HostSpecDto::from(&stored.host.spec),
            revision: stored.revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{CertificateOrigin, HostId};

    #[test]
    fn dead_spec_uses_the_tagged_shape_without_a_content_object() {
        let value = serde_json::to_value(HostSpecDto::Dead).unwrap();
        assert_eq!(value, serde_json::json!({"kind": "dead"}));
        let decoded: HostSpecDto = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, HostSpecDto::Dead);
    }

    #[test]
    fn npm_field_names_are_rejected() {
        let error = serde_json::from_value::<HostWriteRequest>(serde_json::json!({
            "domains": ["app.example.com"],
            "forward_host": "10.0.0.5",
            "spec": {"kind": "dead"}
        }))
        .expect_err("NPM fields must not be accepted by the native schema");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn write_defaults_to_enabled_and_disabled_tls() {
        let request: HostWriteRequest = serde_json::from_value(serde_json::json!({
            "domains": ["app.example.com"],
            "spec": {"kind": "dead"}
        }))
        .unwrap();
        assert!(request.enabled);
        assert_eq!(request.tls.mode, TlsMode::Disabled);
    }

    #[test]
    fn response_round_trips_a_manual_host() {
        let mut host = Host::new(
            HostId(7),
            vec!["app.example.com".to_string()],
            HostTls::for_explicit(CertificateId(3), CertificateOrigin::Manual),
            HostSpec::Proxy(ProxySpec::new(Upstream::new(
                UpstreamScheme::Https,
                "10.0.0.5",
                8443,
            ))),
        );
        host.enabled = false;
        let stored = StoredHost { host, revision: 4 };
        let response = HostResponse::from(&stored);
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["revision"], 4);
        assert_eq!(value["enabled"], false);
        assert_eq!(value["tls"]["certificateId"], 3);
        assert_eq!(value["spec"]["kind"], "proxy");
        assert!(value.get("forwardHost").is_none());
        let decoded: HostResponse = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, response);
    }
}
