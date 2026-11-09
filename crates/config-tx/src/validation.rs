//! Configuration structure validation.

use serde_json::Value;
use thiserror::Error;

/// Error from config structure validation.
#[derive(Debug, Error)]
#[error("config validation error at {path}: {message}")]
pub struct ConfigStructureError {
    /// JSON path to the error.
    pub path: String,
    /// Error message.
    pub message: String,
}

/// Validate that a JSON value is a valid Caddy config structure.
///
/// This performs structural validation only (apps.http, apps.tls, etc.),
/// not semantic validation.
pub fn validate_config_structure(config: &Value) -> Result<(), ConfigStructureError> {
    // Must be an object
    let obj = config.as_object().ok_or_else(|| ConfigStructureError {
        path: "".to_string(),
        message: "config must be a JSON object".to_string(),
    })?;

    // Check for known top-level keys
    let known_keys = ["admin", "logging", "storage", "apps", "pki"];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: key.clone(),
                message: format!("unknown top-level key: {}", key),
            });
        }
    }

    // Validate apps if present
    if let Some(apps) = obj.get("apps").and_then(|v| v.as_object()) {
        validate_apps(apps)?;
    }

    // Validate admin if present
    if let Some(admin) = obj.get("admin") {
        validate_admin(admin, "admin")?;
    }

    // Validate logging if present
    if let Some(logging) = obj.get("logging") {
        validate_logging(logging, "logging")?;
    }

    // Validate storage if present
    if let Some(storage) = obj.get("storage") {
        validate_storage(storage, "storage")?;
    }

    // Validate pki if present
    if let Some(pki) = obj.get("pki") {
        validate_pki(pki, "pki")?;
    }

    Ok(())
}

/// Validate apps structure.
fn validate_apps(apps: &serde_json::Map<String, Value>) -> Result<(), ConfigStructureError> {
    let known_apps = ["http", "tls", "pki", "layer4"];

    for (key, value) in apps {
        if !known_apps.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("apps.{}", key),
                message: format!("unknown app module: {}", key),
            });
        }

        match key.as_str() {
            "http" => validate_http_app(value, "apps.http")?,
            "tls" => validate_tls_app(value, "apps.tls")?,
            "pki" => validate_pki_app(value, "apps.pki")?,
            "layer4" => validate_layer4_app(value, "apps.layer4")?,
            _ => {}
        }
    }

    Ok(())
}

/// Validate HTTP app structure.
fn validate_http_app(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "http app must be an object".to_string(),
    })?;

    // Mirror the JSON fields of caddyhttp.App in the pinned Caddy oracle. Anything else here is
    // not accepted by Caddy and must not pass staging either.
    let known_keys = [
        "servers",
        "grace_period",
        "http_port",
        "https_port",
        "shutdown_delay",
        "metrics",
    ];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown http app key: {}", key),
            });
        }
    }

    // Validate servers
    if let Some(servers) = obj.get("servers").and_then(|v| v.as_object()) {
        for (server_name, server) in servers {
            validate_server(server, &format!("{}.servers.{}", path, server_name))?;
        }
    }

    Ok(())
}

/// JSON fields of caddyhttp.Server in the pinned Caddy v2.11.9 oracle.
const SERVER_KEYS: &[&str] = &[
    "allow_0rtt",
    "automatic_https",
    "client_ip_headers",
    "enable_full_duplex",
    "errors",
    "expected_dot_headers",
    "expected_underscore_headers",
    "idle_timeout",
    "keepalive_count",
    "keepalive_idle",
    "keepalive_interval",
    "listen",
    "listen_protocols",
    "listener_wrappers",
    "logs",
    "max_header_bytes",
    "max_write_chunk",
    "metrics",
    "named_routes",
    "packet_conn_wrappers",
    "protocols",
    "read_header_timeout",
    "read_idle_timeout",
    "read_min_rate",
    "read_timeout",
    "routes",
    "strict_sni_host",
    "tls_connection_policies",
    "trusted_proxies",
    "trusted_proxies_strict",
    "trusted_proxies_unix",
    "write_idle_timeout",
    "write_min_rate",
    "write_timeout",
];

/// Validate a server configuration.
fn validate_server(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "server must be an object".to_string(),
    })?;

    // Mirror caddyhttp.Server in the pinned Caddy oracle. Keep this exact: accepting a key Caddy
    // rejects would make staging pass and the later `/load` fail; omitting a real field would
    // reject a document Caddy accepts.
    for key in obj.keys() {
        if !SERVER_KEYS.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown server key: {}", key),
            });
        }
    }

    // Validate routes if present
    if let Some(routes) = obj.get("routes").and_then(|v| v.as_array()) {
        for (i, route) in routes.iter().enumerate() {
            validate_route(route, &format!("{}.routes[{}]", path, i))?;
        }
    }

    Ok(())
}

/// Validate a route configuration.
fn validate_route(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "route must be an object".to_string(),
    })?;

    let known_keys = [
        "@id",
        "match",
        "handle",
        "handle_path",
        "handle_error",
        "terminal",
        "group",
    ];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown route key: {}", key),
            });
        }
    }

    // @id should be a string if present
    if let Some(id) = obj.get("@id") {
        if !id.is_string() {
            return Err(ConfigStructureError {
                path: format!("{}.@id", path),
                message: "@id must be a string".to_string(),
            });
        }
    }

    Ok(())
}

/// Validate TLS app structure.
fn validate_tls_app(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "tls app must be an object".to_string(),
    })?;

    let known_keys = ["certificates", "automation", "config_defaults", "key_types"];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown tls app key: {}", key),
            });
        }
    }

    Ok(())
}

/// Validate PKI app structure.
fn validate_pki_app(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "pki app must be an object".to_string(),
    })?;

    let known_keys = ["certificate_authorities", "certificates"];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown pki app key: {}", key),
            });
        }
    }

    Ok(())
}

/// Validate layer4 app structure.
fn validate_layer4_app(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "layer4 app must be an object".to_string(),
    })?;

    let known_keys = ["servers", "handles"];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown layer4 app key: {}", key),
            });
        }
    }

    Ok(())
}

/// Validate admin structure.
fn validate_admin(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    if let Some(obj) = value.as_object() {
        let known_keys = [
            "listen",
            "disabled",
            "origins",
            "enforce_origin",
            "config",
            "tls",
        ];

        for key in obj.keys() {
            if !known_keys.contains(&key.as_str()) {
                return Err(ConfigStructureError {
                    path: format!("{}.{}", path, key),
                    message: format!("unknown admin key: {}", key),
                });
            }
        }
    }
    Ok(())
}

/// Validate logging structure.
fn validate_logging(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    if let Some(obj) = value.as_object() {
        let known_keys = ["logs", "default", "excluded"];

        for key in obj.keys() {
            if !known_keys.contains(&key.as_str()) {
                return Err(ConfigStructureError {
                    path: format!("{}.{}", path, key),
                    message: format!("unknown logging key: {}", key),
                });
            }
        }
    }
    Ok(())
}

/// Validate storage structure.
fn validate_storage(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    if let Some(obj) = value.as_object() {
        let known_keys = ["module", "config"];

        for key in obj.keys() {
            if !known_keys.contains(&key.as_str()) {
                return Err(ConfigStructureError {
                    path: format!("{}.{}", path, key),
                    message: format!("unknown storage key: {}", key),
                });
            }
        }
    }
    Ok(())
}

/// Validate PKI top-level structure.
fn validate_pki(value: &Value, path: &str) -> Result<(), ConfigStructureError> {
    let obj = value.as_object().ok_or_else(|| ConfigStructureError {
        path: path.to_string(),
        message: "pki must be an object".to_string(),
    })?;

    let known_keys = ["certificate_authorities"];

    for key in obj.keys() {
        if !known_keys.contains(&key.as_str()) {
            return Err(ConfigStructureError {
                path: format!("{}.{}", path, key),
                message: format!("unknown pki key: {}", key),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_config() {
        let config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":80"],
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]}
                            ]
                        }
                    }
                }
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_invalid_top_level_key() {
        let config = json!({
            "unknown_key": {},
            "apps": {}
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "unknown_key");
        assert!(err.message.contains("unknown top-level key"));
    }

    #[test]
    fn test_invalid_app_module() {
        let config = json!({
            "apps": {
                "unknown_app": {}
            }
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "apps.unknown_app");
        assert!(err.message.contains("unknown app module"));
    }

    #[test]
    fn test_invalid_http_key() {
        let config = json!({
            "apps": {
                "http": {
                    "unknown_key": {}
                }
            }
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "apps.http.unknown_key");
        assert!(err.message.contains("unknown http app key"));
    }

    #[test]
    fn test_http_app_accepts_caddy_port_and_grace_fields() {
        let config = json!({
            "apps": {
                "http": {
                    "http_port": 8080,
                    "https_port": 8443,
                    "grace_period": 5000000000_u64,
                    "shutdown_delay": 1000000000_u64
                }
            }
        });
        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_server_accepts_every_pinned_caddy_server_field() {
        for field in SERVER_KEYS {
            let mut server = serde_json::Map::new();
            server.insert((*field).to_string(), json!({}));
            let config = json!({
                "apps": {
                    "http": {
                        "servers": {
                            "pm": serde_json::Value::Object(server)
                        }
                    }
                }
            });
            validate_config_structure(&config)
                .unwrap_or_else(|error| panic!("field {field} rejected: {error:?}"));
        }
    }

    #[test]
    fn test_server_accepts_caddy_automatic_https_and_timeout_fields() {
        let config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "pm": {
                            "listen": [":443"],
                            "automatic_https": {"disable": true},
                            "max_header_bytes": 16384,
                            "keepalive_interval": 30000000000_u64
                        }
                    }
                }
            }
        });
        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_invalid_server_key() {
        let config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "unknown_key": {}
                        }
                    }
                }
            }
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "apps.http.servers.srv0.unknown_key");
        assert!(err.message.contains("unknown server key"));
    }

    #[test]
    fn test_invalid_route_key() {
        let config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"unknown_key": "value"}
                            ]
                        }
                    }
                }
            }
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "apps.http.servers.srv0.routes[0].unknown_key");
        assert!(err.message.contains("unknown route key"));
    }

    #[test]
    fn test_invalid_at_id_type() {
        let config = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": 123}
                            ]
                        }
                    }
                }
            }
        });

        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "apps.http.servers.srv0.routes[0].@id");
        assert!(err.message.contains("@id must be a string"));
    }

    #[test]
    fn test_valid_tls_app() {
        let config = json!({
            "apps": {
                "tls": {
                    "certificates": []
                }
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_valid_pki_app() {
        let config = json!({
            "apps": {
                "pki": {
                    "certificate_authorities": []
                }
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_valid_admin() {
        let config = json!({
            "admin": {
                "listen": "localhost:2019"
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_valid_logging() {
        let config = json!({
            "logging": {
                "logs": {}
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_valid_storage() {
        let config = json!({
            "storage": {
                "module": "standard"
            }
        });

        assert!(validate_config_structure(&config).is_ok());
    }

    #[test]
    fn test_config_must_be_object() {
        let config = json!("not an object");
        let err = validate_config_structure(&config).unwrap_err();
        assert_eq!(err.path, "");
        assert!(err.message.contains("must be a JSON object"));
    }
}
