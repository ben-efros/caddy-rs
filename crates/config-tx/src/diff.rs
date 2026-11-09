//! Diff computation between configuration generations.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Type of change in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffKind {
    Added,
    Removed,
    Modified,
}

/// A single change in the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffChange {
    /// Kind of change.
    pub kind: DiffKind,
    /// Route @id if available.
    pub route_id: Option<String>,
    /// JSON path to the changed element.
    pub path: String,
    /// Old value (for removed/modified).
    pub old_value: Option<Value>,
    /// New value (for added/modified).
    pub new_value: Option<Value>,
}

/// Diff between two configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    /// List of changes.
    pub changes: Vec<DiffChange>,
}

impl Diff {
    /// Check if the diff is empty (no changes).
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Compute diff between two configurations by comparing routes via @id.
pub fn compute_diff(old: &Value, new: &Value) -> Diff {
    let mut changes = Vec::new();

    // Extract routes from both configs
    let old_routes = extract_routes(old);
    let new_routes = extract_routes(new);

    // Find added and modified routes
    for (id, new_route) in &new_routes {
        if let Some(old_route) = old_routes.get(id) {
            if old_route != new_route {
                changes.push(DiffChange {
                    kind: DiffKind::Modified,
                    route_id: Some(id.clone()),
                    path: format!("routes[@id='{}']", id),
                    old_value: Some(old_route.clone()),
                    new_value: Some(new_route.clone()),
                });
            }
        } else {
            changes.push(DiffChange {
                kind: DiffKind::Added,
                route_id: Some(id.clone()),
                path: format!("routes[@id='{}']", id),
                old_value: None,
                new_value: Some(new_route.clone()),
            });
        }
    }

    // Find removed routes
    for (id, old_route) in &old_routes {
        if !new_routes.contains_key(id) {
            changes.push(DiffChange {
                kind: DiffKind::Removed,
                route_id: Some(id.clone()),
                path: format!("routes[@id='{}']", id),
                old_value: Some(old_route.clone()),
                new_value: None,
            });
        }
    }

    // Also diff top-level structure for non-route changes
    diff_values(&mut changes, "", old, new);

    // Routes without an @id are not covered by the keyed pass. Emit them explicitly so an unkeyed
    // route edit cannot silently produce an empty diff.
    diff_unkeyed_routes(&mut changes, old, new);

    Diff { changes }
}

fn route_id(route: &Value) -> Option<&str> {
    route.get("@id").and_then(Value::as_str)
}

fn server_routes(config: &Value) -> HashMap<&str, &Vec<Value>> {
    let mut routes = HashMap::new();
    if let Some(servers) = config
        .get("apps")
        .and_then(|apps| apps.get("http"))
        .and_then(|http| http.get("servers"))
        .and_then(Value::as_object)
    {
        for (name, server) in servers {
            if let Some(array) = server.get("routes").and_then(Value::as_array) {
                routes.insert(name.as_str(), array);
            }
        }
    }
    routes
}

fn diff_unkeyed_routes(changes: &mut Vec<DiffChange>, old: &Value, new: &Value) {
    let old_servers = server_routes(old);
    let new_servers = server_routes(new);
    let mut names: Vec<&str> = old_servers
        .keys()
        .chain(new_servers.keys())
        .copied()
        .collect();
    names.sort_unstable();
    names.dedup();

    for name in names {
        let old_routes = old_servers.get(name).copied();
        let new_routes = new_servers.get(name).copied();
        let length = old_routes
            .map_or(0, Vec::len)
            .max(new_routes.map_or(0, Vec::len));
        for index in 0..length {
            let old_route = old_routes.and_then(|routes| routes.get(index));
            let new_route = new_routes.and_then(|routes| routes.get(index));
            let path = format!("apps.http.servers.{name}.routes[{index}]");

            match (old_route, new_route) {
                (Some(old_route), Some(new_route)) => {
                    match (route_id(old_route), route_id(new_route)) {
                        // Both keyed: the keyed pass owns this change.
                        (Some(_), Some(_)) => {}
                        (None, None) if old_route == new_route => {}
                        (None, None) => changes.push(DiffChange {
                            kind: DiffKind::Modified,
                            route_id: None,
                            path,
                            old_value: Some(old_route.clone()),
                            new_value: Some(new_route.clone()),
                        }),
                        // One side is keyed and therefore already reported as added/removed.
                        (None, Some(_)) => changes.push(DiffChange {
                            kind: DiffKind::Removed,
                            route_id: None,
                            path,
                            old_value: Some(old_route.clone()),
                            new_value: None,
                        }),
                        (Some(_), None) => changes.push(DiffChange {
                            kind: DiffKind::Added,
                            route_id: None,
                            path,
                            old_value: None,
                            new_value: Some(new_route.clone()),
                        }),
                    }
                }
                (Some(old_route), None) if route_id(old_route).is_none() => {
                    changes.push(DiffChange {
                        kind: DiffKind::Removed,
                        route_id: None,
                        path,
                        old_value: Some(old_route.clone()),
                        new_value: None,
                    });
                }
                (None, Some(new_route)) if route_id(new_route).is_none() => {
                    changes.push(DiffChange {
                        kind: DiffKind::Added,
                        route_id: None,
                        path,
                        old_value: None,
                        new_value: Some(new_route.clone()),
                    });
                }
                _ => {}
            }
        }
    }
}

/// Extract routes from a config, keyed by @id.
fn extract_routes(config: &Value) -> HashMap<String, Value> {
    let mut routes = HashMap::new();

    if let Some(apps) = config.get("apps").and_then(|a| a.as_object()) {
        if let Some(http) = apps.get("http").and_then(|h| h.as_object()) {
            if let Some(servers) = http.get("servers").and_then(|s| s.as_object()) {
                for (_, server) in servers {
                    if let Some(server_routes) = server.get("routes").and_then(|r| r.as_array()) {
                        for route in server_routes {
                            if let Some(route_obj) = route.as_object() {
                                if let Some(id) = route_obj.get("@id").and_then(|v| v.as_str()) {
                                    routes.insert(id.to_string(), route.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    routes
}

/// Recursively diff two JSON values.
fn diff_values(changes: &mut Vec<DiffChange>, path: &str, old: &Value, new: &Value) {
    // Skip route-level changes as they're handled separately by extract_routes
    if is_route_path(path) {
        return;
    }

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            let all_keys: std::collections::HashSet<_> =
                old_map.keys().chain(new_map.keys()).collect();

            for key in all_keys {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };

                match (old_map.get(key), new_map.get(key)) {
                    (Some(old_val), Some(new_val)) => {
                        diff_values(changes, &new_path, old_val, new_val);
                    }
                    (None, Some(new_val)) => {
                        if !is_route_path(&new_path) {
                            changes.push(DiffChange {
                                kind: DiffKind::Added,
                                route_id: None,
                                path: new_path,
                                old_value: None,
                                new_value: Some(new_val.clone()),
                            });
                        }
                    }
                    (Some(old_val), None) => {
                        if !is_route_path(&new_path) {
                            changes.push(DiffChange {
                                kind: DiffKind::Removed,
                                route_id: None,
                                path: new_path,
                                old_value: Some(old_val.clone()),
                                new_value: None,
                            });
                        }
                    }
                    (None, None) => {}
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            // For arrays, do a simple comparison - if different, mark as modified
            // Only if not a routes array
            if old_arr != new_arr && !is_route_path(path) {
                changes.push(DiffChange {
                    kind: DiffKind::Modified,
                    route_id: None,
                    path: path.to_string(),
                    old_value: Some(Value::Array(old_arr.clone())),
                    new_value: Some(Value::Array(new_arr.clone())),
                });
            }
        }
        (old_val, new_val) if old_val != new_val && !is_route_path(path) => {
            changes.push(DiffChange {
                kind: DiffKind::Modified,
                route_id: None,
                path: path.to_string(),
                old_value: Some(old_val.clone()),
                new_value: Some(new_val.clone()),
            });
        }
        _ => {}
    }
}

/// Check if a JSON path is within a routes array (to avoid double-counting route changes).
fn is_route_path(path: &str) -> bool {
    // Match the routes array itself ("apps.http.servers.srv0.routes") and anything inside it
    // ("...routes[0].handle"). Route changes are emitted once, by route @id, above; recursing into
    // the array would add a second, array-level Modified entry for the same change.
    path.ends_with(".routes") || path.contains(".routes[")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_diff_added_route() {
        let old = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]}
                            ]
                        }
                    }
                }
            }
        });

        let new = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]},
                                {"@id": "host2", "handle": [{"handler": "static_response", "body": "World"}]}
                            ]
                        }
                    }
                }
            }
        });

        let diff = compute_diff(&old, &new);
        let added: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.kind == DiffKind::Added)
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].route_id, Some("host2".to_string()));
    }

    #[test]
    fn test_compute_diff_removed_route() {
        let old = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]},
                                {"@id": "host2", "handle": [{"handler": "static_response", "body": "World"}]}
                            ]
                        }
                    }
                }
            }
        });

        let new = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]}
                            ]
                        }
                    }
                }
            }
        });

        let diff = compute_diff(&old, &new);
        let removed: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.kind == DiffKind::Removed)
            .collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].route_id, Some("host2".to_string()));
    }

    #[test]
    fn test_compute_diff_modified_route_without_id() {
        let old = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"handle": [{"handler": "static_response", "body": "Hello"}]}
                            ]
                        }
                    }
                }
            }
        });
        let new = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"handle": [{"handler": "static_response", "body": "World"}]}
                            ]
                        }
                    }
                }
            }
        });

        let diff = compute_diff(&old, &new);
        assert_eq!(diff.changes.len(), 1, "unkeyed edit must produce one entry");
        let change = &diff.changes[0];
        assert_eq!(change.kind, DiffKind::Modified);
        assert_eq!(change.route_id, None);
        assert_eq!(change.path, "apps.http.servers.srv0.routes[0]");
    }

    #[test]
    fn test_compute_diff_modified_route() {
        let old = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "Hello"}]}
                            ]
                        }
                    }
                }
            }
        });

        let new = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "routes": [
                                {"@id": "host1", "handle": [{"handler": "static_response", "body": "World"}]}
                            ]
                        }
                    }
                }
            }
        });

        let diff = compute_diff(&old, &new);
        let modified: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.kind == DiffKind::Modified)
            .collect();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].route_id, Some("host1".to_string()));
    }
}
