//! Configuration validation.
//!
//! Validation is the gate between "decoded JSON" and "provisionable configuration generation".
//! It walks every handler and matcher reference, so an unsupported module fails at validation
//! time with a located error instead of at request time. It also enforces the structural
//! invariants this implementation relies on: unique route ids, unique listeners, and well-formed
//! reverse-proxy upstreams.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::config::{Config, HttpApp, Route, TlsApp};
use crate::error::{Error, Result};
use crate::listen::ListenAddr;
use crate::module::{ModuleKind, ModuleRegistry};

/// Counts produced by a successful validation walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// HTTP servers inspected.
    pub servers: usize,
    /// Routes inspected, including nested subroutes.
    pub routes: usize,
    /// Handler modules inspected.
    pub handlers: usize,
    /// Matcher modules inspected.
    pub matchers: usize,
    /// TLS automation policies inspected.
    pub tls_policies: usize,
}

/// Validate a configuration against a module registry.
pub fn validate_config(config: &Config, registry: &ModuleRegistry) -> Result<ValidationReport> {
    let mut validator = Validator {
        registry,
        ids: BTreeSet::new(),
        report: ValidationReport::default(),
    };

    if !config.extra.is_empty() {
        let fields: Vec<&str> = config.extra.keys().map(String::as_str).collect();
        return Err(Error::invalid(
            "",
            format!(
                "unknown top-level configuration field(s): {}",
                fields.join(", ")
            ),
        ));
    }

    if let Some(admin) = &config.admin {
        if let Some(listen) = &admin.listen {
            ListenAddr::parse_at(listen, "admin.listen")?;
        }
    }

    if let Some(storage) = &config.storage {
        validate_storage(storage, registry)?;
    }

    match &config.apps {
        None => {}
        Some(apps) => {
            if !apps.extra.is_empty() {
                let apps_unknown: Vec<&str> = apps.extra.keys().map(String::as_str).collect();
                return Err(Error::invalid(
                    "apps",
                    format!(
                        "unknown app module(s): {}; this build supports `http` and `tls`",
                        apps_unknown.join(", ")
                    ),
                ));
            }
            if let Some(http) = &apps.http {
                validator.http(http)?;
            }
            if let Some(tls) = &apps.tls {
                validator.tls(tls)?;
            }
        }
    }

    Ok(validator.report)
}

fn validate_storage(storage: &Value, registry: &ModuleRegistry) -> Result<()> {
    let object = storage
        .as_object()
        .ok_or_else(|| Error::invalid("storage", "storage must be an object"))?;
    let module = object
        .get("module")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("storage.module", "storage object must name a `module`"))?;
    if registry.get_by_key(ModuleKind::Storage, module).is_none() {
        return Err(Error::UnknownModule {
            kind: "storage",
            name: module.to_string(),
            path: "storage.module".to_string(),
        });
    }
    Ok(())
}

struct Validator<'a> {
    registry: &'a ModuleRegistry,
    ids: BTreeSet<String>,
    report: ValidationReport,
}

impl Validator<'_> {
    fn http(&mut self, http: &HttpApp) -> Result<()> {
        if !http.extra.is_empty() {
            let fields: Vec<&str> = http.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid(
                "apps.http",
                format!("unknown HTTP app field(s): {}", fields.join(", ")),
            ));
        }

        let mut listeners: BTreeMap<&str, &str> = BTreeMap::new();
        for (server_name, server) in &http.servers {
            let server_path = format!("apps.http.servers.{server_name}");
            if server.listen.is_empty() {
                return Err(Error::invalid(
                    format!("{server_path}.listen"),
                    "server must declare at least one listen address",
                ));
            }
            for (index, listen) in server.listen.iter().enumerate() {
                let path = format!("{server_path}.listen[{index}]");
                ListenAddr::parse_at(listen, path)?;
                if let Some(previous) = listeners.insert(listen.as_str(), server_name) {
                    return Err(Error::invalid(
                        format!("{server_path}.listen[{index}]"),
                        format!(
                            "duplicate listener `{listen}`: already used by server `{previous}`"
                        ),
                    ));
                }
            }
            if let Some(automatic_https) = &server.automatic_https {
                if !automatic_https.extra.is_empty() {
                    let fields: Vec<&str> =
                        automatic_https.extra.keys().map(String::as_str).collect();
                    return Err(Error::invalid(
                        format!("{server_path}.automatic_https"),
                        format!("unknown automatic_https field(s): {}", fields.join(", ")),
                    ));
                }
            }
            self.routes(&server.routes, &format!("{server_path}.routes"))?;
            self.report.servers += 1;
        }
        Ok(())
    }

    fn routes(&mut self, routes: &[Route], base: &str) -> Result<()> {
        for (index, route) in routes.iter().enumerate() {
            let route_path = format!("{base}[{index}]");
            if let Some(id) = &route.id {
                if id.trim().is_empty() {
                    return Err(Error::invalid(
                        format!("{route_path}.@id"),
                        "route id must not be empty",
                    ));
                }
                if !self.ids.insert(id.clone()) {
                    return Err(Error::invalid(
                        format!("{route_path}.@id"),
                        format!("duplicate route id `{id}`"),
                    ));
                }
            }
            for (handler_index, handler) in route.handle.iter().enumerate() {
                self.handler(handler, &format!("{route_path}.handle[{handler_index}]"))?;
            }
            for (set_index, set) in route.matcher_sets.iter().enumerate() {
                self.matcher_set(set, &format!("{route_path}.match[{set_index}]"))?;
            }
            self.report.routes += 1;
        }
        Ok(())
    }

    fn handler(&mut self, value: &Value, path: &str) -> Result<()> {
        let object = value.as_object().ok_or_else(|| {
            Error::invalid(path, "handler must be a JSON object with a `handler` key")
        })?;
        let name = object
            .get("handler")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::invalid(path, "handler object is missing string field `handler`")
            })?;
        let module = self
            .registry
            .resolve_handler(name)
            .ok_or_else(|| Error::UnknownModule {
                kind: "HTTP handler",
                name: name.to_string(),
                path: format!("{path}.handler"),
            })?;
        self.report.handlers += 1;

        match module.json_key {
            "subroute" => {
                let nested = object
                    .get("routes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        Error::invalid(
                            format!("{path}.routes"),
                            "subroute handler requires an array field `routes`",
                        )
                    })?;
                let decoded: Vec<Route> = serde_json::from_value(Value::Array(nested.clone()))
                    .map_err(|source| {
                        Error::invalid(
                            format!("{path}.routes"),
                            format!("cannot decode nested routes: {source}"),
                        )
                    })?;
                self.routes(&decoded, &format!("{path}.routes"))?;
            }
            "reverse_proxy" => {
                let upstreams = object
                    .get("upstreams")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        Error::invalid(
                            format!("{path}.upstreams"),
                            "reverse_proxy requires an array field `upstreams`",
                        )
                    })?;
                if upstreams.is_empty() {
                    return Err(Error::invalid(
                        format!("{path}.upstreams"),
                        "reverse_proxy requires at least one upstream",
                    ));
                }
                for (index, upstream) in upstreams.iter().enumerate() {
                    let upstream_path = format!("{path}.upstreams[{index}]");
                    let upstream_object = upstream.as_object().ok_or_else(|| {
                        Error::invalid(&upstream_path, "upstream must be a JSON object")
                    })?;
                    match upstream_object.get("dial").and_then(Value::as_str) {
                        Some(dial) if !dial.trim().is_empty() => {}
                        _ => {
                            return Err(Error::invalid(
                                format!("{upstream_path}.dial"),
                                "upstream must declare a non-empty string `dial`",
                            ))
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn matcher_set(&mut self, value: &Value, path: &str) -> Result<()> {
        let object = value
            .as_object()
            .ok_or_else(|| Error::invalid(path, "matcher set must be a JSON object"))?;
        if object.is_empty() {
            return Ok(());
        }
        for (key, matcher) in object {
            if key == "not" {
                let nested = matcher.as_array().ok_or_else(|| {
                    Error::invalid(
                        format!("{path}.not"),
                        "`not` must be an array of matcher sets",
                    )
                })?;
                for (index, set) in nested.iter().enumerate() {
                    self.matcher_set(set, &format!("{path}.not[{index}]"))?;
                }
                continue;
            }
            if self.registry.resolve_matcher(key).is_none() {
                return Err(Error::UnknownModule {
                    kind: "HTTP matcher",
                    name: key.clone(),
                    path: format!("{path}.{key}"),
                });
            }
            self.report.matchers += 1;
        }
        Ok(())
    }

    fn tls(&mut self, tls: &TlsApp) -> Result<()> {
        if let Some(automation) = &tls.automation {
            let Some(automation) = automation.as_object() else {
                return Err(Error::invalid(
                    "apps.tls.automation",
                    "automation must be an object",
                ));
            };
            if let Some(policies) = automation.get("policies") {
                let Some(policies) = policies.as_array() else {
                    return Err(Error::invalid(
                        "apps.tls.automation.policies",
                        "policies must be an array",
                    ));
                };
                for (index, policy) in policies.iter().enumerate() {
                    let path = format!("apps.tls.automation.policies[{index}]");
                    self.tls_policy(policy, &path)?;
                }
            }
        }
        Ok(())
    }

    fn tls_policy(&mut self, policy: &Value, path: &str) -> Result<()> {
        let object = policy
            .as_object()
            .ok_or_else(|| Error::invalid(path, "TLS automation policy must be an object"))?;
        self.report.tls_policies += 1;
        if let Some(issuers) = object.get("issuers") {
            let issuers = issuers.as_array().ok_or_else(|| {
                Error::invalid(format!("{path}.issuers"), "issuers must be an array")
            })?;
            for (index, issuer) in issuers.iter().enumerate() {
                let issuer_path = format!("{path}.issuers[{index}]");
                let issuer_object = issuer
                    .as_object()
                    .ok_or_else(|| Error::invalid(&issuer_path, "issuer must be an object"))?;
                let module = issuer_object
                    .get("module")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Error::invalid(
                            format!("{issuer_path}.module"),
                            "issuer must name a `module`",
                        )
                    })?;
                if self
                    .registry
                    .get_by_key(ModuleKind::TlsIssuer, module)
                    .is_none()
                {
                    return Err(Error::UnknownModule {
                        kind: "TLS issuer",
                        name: module.to_string(),
                        path: format!("{issuer_path}.module"),
                    });
                }
                self.validate_dns_provider(issuer_object, &issuer_path)?;
            }
        }
        Ok(())
    }

    fn validate_dns_provider(
        &self,
        issuer: &serde_json::Map<String, Value>,
        path: &str,
    ) -> Result<()> {
        let provider = issuer
            .get("challenges")
            .and_then(|c| c.get("dns"))
            .and_then(|d| d.get("provider"))
            .and_then(Value::as_str);
        if let Some(provider) = provider {
            if self
                .registry
                .get_by_key(ModuleKind::DnsProvider, provider)
                .is_none()
            {
                return Err(Error::UnknownModule {
                    kind: "DNS provider",
                    name: provider.to_string(),
                    path: format!("{path}.challenges.dns.provider"),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ModuleRegistry {
        ModuleRegistry::builtin()
    }

    fn minimal_http_config(handler: Value, matcher: Option<Value>) -> Config {
        let mut route = serde_json::json!({
            "handle": [handler],
        });
        if let Some(matcher) = matcher {
            route["match"] = serde_json::json!([matcher]);
        }
        Config::from_value(serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":443"],
                            "routes": [route]
                        }
                    }
                }
            }
        }))
        .expect("model decodes")
    }

    #[test]
    fn accepts_known_handler_and_matcher() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "static_response", "body": "ok"}),
            Some(serde_json::json!({"host": ["example.com"]})),
        );
        let report = validate_config(&config, &registry()).expect("valid");
        assert_eq!(report.servers, 1);
        assert_eq!(report.handlers, 1);
        assert_eq!(report.matchers, 1);
    }

    #[test]
    fn rejects_unknown_handler_with_path_and_name() {
        let config = minimal_http_config(serde_json::json!({"handler": "does_not_exist"}), None);
        let error = validate_config(&config, &registry()).expect_err("unknown handler");
        let message = error.to_string();
        assert!(message.contains("does_not_exist"), "{message}");
        assert!(message.contains("handle[0]"), "{message}");
    }

    #[test]
    fn rejects_unknown_app() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"events": {}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("unknown app");
        assert!(error.to_string().contains("events"));
    }

    #[test]
    fn rejects_duplicate_route_ids() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":80"],
                "routes": [
                    {"@id": "same", "handle": [{"handler": "static_response"}]},
                    {"@id": "same", "handle": [{"handler": "static_response"}]}
                ]
            }}}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("duplicate id");
        assert!(error.to_string().contains("duplicate route id `same`"));
    }

    #[test]
    fn rejects_invalid_listen_address() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": ["not-an-address"],
                "routes": []
            }}}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("bad listen");
        assert!(error.to_string().contains("not-an-address"));
    }

    #[test]
    fn rejects_duplicate_listener_across_servers() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {
                "srv0": {"listen": [":443"], "routes": []},
                "srv1": {"listen": [":443"], "routes": []}
            }}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("duplicate listener");
        assert!(error.to_string().contains("already used by server `srv0`"));
    }

    #[test]
    fn validates_nested_subroute_handlers() {
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "subroute",
                "routes": [{"handle": [{"handler": "bogus_nested"}]}]
            }),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("nested unknown handler");
        assert!(error.to_string().contains("bogus_nested"));
    }

    #[test]
    fn rejects_reverse_proxy_without_upstreams() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "reverse_proxy", "upstreams": []}),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("no upstreams");
        assert!(error.to_string().contains("at least one upstream"));
    }
}
