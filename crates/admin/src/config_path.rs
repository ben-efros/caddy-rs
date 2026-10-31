//! Caddy-compatible JSON configuration path traversal, indexing, and mutation.
//!
//! This is a faithful port of the path semantics used by upstream Caddy's
//! `admin.go`/`caddy.go`:
//!
//! - `unsyncedConfigAccess` (traversal + method semantics, including the array `...` expansion),
//! - `indexConfigObjects` (`@id` indexing and duplicate detection),
//! - `handleConfigID` (`/id/<id>` path expansion).
//!
//! Paths are the URL path with the leading `/` trimmed and split on `/`, starting with the
//! `config` key because Caddy stores the active configuration under `rawCfg["config"]`. We
//! reproduce that wrapper so root-level operations (`POST/PATCH/DELETE /config/`) behave like
//! Caddy rather than inventing a special case.
//!
//! Key semantics replicated exactly:
//!
//! | Operation | Object key (terminal) | Array element (terminal) | Existing array (POST terminal) |
//! |---|---|---|---|
//! | `POST` | set (or append if the value is an array) | appends, ignoring the index | append |
//! | `PUT` | 409 if the key exists, otherwise set | insert at index (`len` allowed) | - |
//! | `PATCH` | 404 if the key is missing, otherwise set | replace at index (must exist) | - |
//! | `DELETE` | 404 if the key is missing, otherwise remove | remove at index (must exist) | - |
//!
//! A trailing `...` path segment means the payload must be an array whose elements are appended
//! to the destination array (`POST /config/.../routes/...`).
//!
//! Deliberate simplifications are documented in [`crate`] and in the task report: malformed
//! bodies/paths return `400` (Caddy wraps unwrapped handler errors as `500`); request bodies are
//! decoded directly with `serde_json` rather than through the JSON-syntax-offset message.

use std::collections::HashMap;

use http::StatusCode;
use serde_json::{Map, Value};

/// A located configuration-path error with the HTTP status it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl PathError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn api(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// The mutating methods accepted on a configuration path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mutation {
    /// Append to the destination array, or set/replace the destination value.
    Post,
    /// Insert into the destination array, or create the destination key.
    Put,
    /// Replace the destination array element or existing object key.
    Patch,
    /// Remove the destination array element or object key.
    Delete,
}

impl Mutation {
    /// Map an HTTP method name to a mutation, if it is one of the config-changing methods.
    pub(crate) fn from_method(method: &str) -> Option<Self> {
        match method {
            "POST" => Some(Mutation::Post),
            "PUT" => Some(Mutation::Put),
            "PATCH" => Some(Mutation::Patch),
            "DELETE" => Some(Mutation::Delete),
            _ => None,
        }
    }
}

/// Navigate a JSON document by relative path segments (object keys or canonical array indexes).
///
/// Returns `None` when any segment is missing or has the wrong shape. Upstream Caddy renders a
/// missing `GET` path as `null`; this crate reports a located 404 instead (documented divergence).
pub(crate) fn navigate<'a>(root: &'a Value, parts: &[&str]) -> Option<&'a Value> {
    let mut current = root;
    for part in parts {
        current = match current {
            Value::Object(map) => map.get(*part)?,
            Value::Array(array) => array.get(parse_canonical_index(part).ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Parse an array index the way Caddy does: no empty string, no non-canonical spelling
/// (`01`, `+1`, `-0`), and no leading/trailing whitespace.
pub(crate) fn parse_canonical_index(index: &str) -> Result<usize, String> {
    if index.is_empty() {
        return Err("empty index".to_string());
    }
    let parsed: i64 = index.parse().map_err(|_| "invalid syntax".to_string())?;
    if parsed.to_string() != index {
        return Err("non-canonical array index".to_string());
    }
    if parsed < 0 {
        // Callers always treat negative indexes as out of bounds afterwards; report the raw
        // value instead of wrapping it into a huge usize.
        return Err("non-canonical array index".to_string());
    }
    Ok(parsed as usize)
}

/// Apply a configuration mutation to `root` (the `{"config": ...}` wrapper), following
/// [`Mutation`] semantics. `parts` are the URL path segments with `/` trimmed.
pub(crate) fn mutate(
    root: &mut Value,
    method: Mutation,
    parts: &[&str],
    ellipses: bool,
    body: Option<&Value>,
) -> Result<(), PathError> {
    if parts.is_empty() {
        return Err(PathError::bad_request("no traversable path"));
    }
    // Upstream formats the full request path in array bounds errors.
    let full_path = format!("/{}", parts.join("/"));
    mutate_at(root, method, parts, 0, ellipses, body, &full_path)
}

fn mutate_at(
    pointer: &mut Value,
    method: Mutation,
    parts: &[&str],
    depth: usize,
    ellipses: bool,
    body: Option<&Value>,
    full_path: &str,
) -> Result<(), PathError> {
    let part = parts[depth];
    let is_last = depth == parts.len() - 1;

    match pointer {
        Value::Object(map) => {
            if is_last {
                return mutate_object_key(map, method, part, ellipses, body, full_path);
            }

            // Caddy special-cases "the next part enters a slice, and the slice is our
            // destination": the array is the second-to-last part and the last part is its index.
            let array_destination =
                depth + 2 == parts.len() && matches!(map.get(part), Some(Value::Array(_)));
            if array_destination {
                let index_part = parts[depth + 1];
                let Value::Array(array) =
                    map.get_mut(part).expect("array destination checked above")
                else {
                    unreachable!("array destination checked above");
                };
                return mutate_array_element(array, method, index_part, ellipses, body, full_path);
            }

            // "If we are PUTting a new resource, the key(s) in its path might not exist yet;
            // that's OK but we need to make them as we go."
            if method == Mutation::Put && matches!(map.get(part), None | Some(Value::Null)) {
                map.insert(part.to_string(), Value::Object(Map::new()));
            }
            let next = map.get_mut(part).ok_or_else(|| {
                PathError::bad_request(format!(
                    "invalid traversal path at: {}",
                    parts[..=depth].join("/")
                ))
            })?;
            mutate_at(next, method, parts, depth + 1, ellipses, body, full_path)
        }
        Value::Array(array) => {
            let index = parse_canonical_index(part).map_err(|reason| {
                PathError::bad_request(format!(
                    "[/{}] invalid array index '{}': {}",
                    parts[..=depth].join("/"),
                    part,
                    reason
                ))
            })?;
            if index >= array.len() {
                return Err(PathError::bad_request(format!(
                    "[/{}] array index out of bounds: {}",
                    parts[..=depth].join("/"),
                    part
                )));
            }
            mutate_at(
                &mut array[index],
                method,
                parts,
                depth + 1,
                ellipses,
                body,
                full_path,
            )
        }
        _ => Err(PathError::bad_request(format!(
            "invalid traversal path at: {}",
            parts[..=depth].join("/")
        ))),
    }
}

/// Terminal object-key mutation (`parts` ends at an object key).
fn mutate_object_key(
    map: &mut Map<String, Value>,
    method: Mutation,
    part: &str,
    ellipses: bool,
    body: Option<&Value>,
    full_path: &str,
) -> Result<(), PathError> {
    match method {
        Mutation::Post => {
            if let Some(Value::Array(array)) = map.get_mut(part) {
                if ellipses {
                    append_expanded(array, body)?;
                } else {
                    array.push(body.cloned().unwrap_or(Value::Null));
                }
            } else {
                map.insert(part.to_string(), body.cloned().unwrap_or(Value::Null));
            }
            Ok(())
        }
        Mutation::Put => {
            if map.contains_key(part) {
                return Err(PathError::api(
                    StatusCode::CONFLICT,
                    format!("[{}] key already exists: {}", full_path, part),
                ));
            }
            map.insert(part.to_string(), body.cloned().unwrap_or(Value::Null));
            Ok(())
        }
        Mutation::Patch => {
            if !map.contains_key(part) {
                return Err(PathError::api(
                    StatusCode::NOT_FOUND,
                    format!("[{}] key does not exist: {}", full_path, part),
                ));
            }
            map.insert(part.to_string(), body.cloned().unwrap_or(Value::Null));
            Ok(())
        }
        Mutation::Delete => {
            if map.remove(part).is_none() {
                return Err(PathError::api(
                    StatusCode::NOT_FOUND,
                    format!("[{}] key does not exist: {}", full_path, part),
                ));
            }
            Ok(())
        }
    }
}

/// Mutation whose destination is a specific array element (terminal index).
fn mutate_array_element(
    array: &mut Vec<Value>,
    method: Mutation,
    index_part: &str,
    ellipses: bool,
    body: Option<&Value>,
    full_path: &str,
) -> Result<(), PathError> {
    if method == Mutation::Post {
        // POST always appends; the index part is not interpreted (matches Caddy).
        if ellipses {
            append_expanded(array, body)?;
        } else {
            array.push(body.cloned().unwrap_or(Value::Null));
        }
        return Ok(());
    }

    let index = parse_canonical_index(index_part).map_err(|reason| {
        PathError::bad_request(format!(
            "[{}] invalid array index '{}': {}",
            full_path, index_part, reason
        ))
    })?;
    let length = array.len();
    if index > length || (method != Mutation::Put && index >= length) {
        return Err(PathError::bad_request(format!(
            "[{}] array index out of bounds: {}",
            full_path, index_part
        )));
    }

    match method {
        Mutation::Put => array.insert(index, body.cloned().unwrap_or(Value::Null)),
        Mutation::Patch => array[index] = body.cloned().unwrap_or(Value::Null),
        Mutation::Delete => {
            array.remove(index);
        }
        Mutation::Post => unreachable!("POST handled above"),
    }
    Ok(())
}

fn append_expanded(array: &mut Vec<Value>, body: Option<&Value>) -> Result<(), PathError> {
    match body {
        Some(Value::Array(elements)) => {
            array.extend(elements.iter().cloned());
            Ok(())
        }
        _ => Err(PathError::bad_request("final element is not an array")),
    }
}

/// Index every object carrying an `@id` field, mapping the id to the path of the *containing*
/// object, relative to the configuration document root (for example
/// `["apps", "http", "servers", "srv0", "routes", "0"]`).
///
/// Duplicate ids and non-string/number ids are rejected, matching upstream `indexConfigObjects`.
pub(crate) fn index_config(root: &Value) -> Result<HashMap<String, Vec<String>>, String> {
    let mut index = HashMap::new();
    let mut path = Vec::new();
    index_value(root, &mut path, &mut index)?;
    Ok(index)
}

fn index_value(
    value: &Value,
    path: &mut Vec<String>,
    index: &mut HashMap<String, Vec<String>>,
) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "@id" {
                    let id = match child {
                        Value::String(id) => id.clone(),
                        Value::Number(number) => number.to_string(),
                        _ => {
                            return Err(format!(
                                "{}: @id field must be a string or number",
                                display_path(path)
                            ))
                        }
                    };
                    if let Some(existing) = index.get(&id) {
                        return Err(format!(
                            "duplicate ID '{}' found at {} and {}",
                            id,
                            display_path(existing),
                            display_path(path)
                        ));
                    }
                    index.insert(id, path.clone());
                    continue;
                }
                path.push(key.clone());
                index_value(child, path, index)?;
                path.pop();
            }
        }
        Value::Array(array) => {
            for (position, child) in array.iter().enumerate() {
                path.push(position.to_string());
                index_value(child, path, index)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

/// Render an indexed path the way Caddy reports it: `/config/apps/...`.
pub(crate) fn display_path(segments: &[String]) -> String {
    if segments.is_empty() {
        "/config".to_string()
    } else {
        format!("/config/{}", segments.join("/"))
    }
}

/// Split a request path into Caddy configuration path segments: leading/trailing `/` trimmed and
/// split on `/`. Empty segments in the middle are preserved (they are invalid array indexes or
/// missing object keys and fail traversal).
pub(crate) fn split_path(path: &str) -> Vec<&str> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('/').collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wrapper() -> Value {
        json!({
            "config": {
                "foo": "bar",
                "list": ["a", "b", "c"],
                "obj": {"nested": 1}
            }
        })
    }

    fn apply(
        value: &mut Value,
        method: Mutation,
        path: &str,
        body: Option<Value>,
        ellipses: bool,
    ) -> Result<(), PathError> {
        let parts = split_path(path);
        mutate(value, method, &parts, ellipses, body.as_ref())
    }

    #[test]
    fn port_of_upstream_unsynced_config_access() {
        // Mirrors upstream `TestUnsyncedConfigAccess` cases.
        let mut value = wrapper();
        apply(
            &mut value,
            Mutation::Post,
            "/config/foo",
            Some(json!("jet")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["foo"], json!("jet"));

        apply(
            &mut value,
            Mutation::Post,
            "/config/bar",
            Some(json!({"aa": "bb", "qq": "zz"})),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["bar"], json!({"aa": "bb", "qq": "zz"}));

        apply(&mut value, Mutation::Delete, "/config/bar/qq", None, false).unwrap();
        assert_eq!(value["config"]["bar"], json!({"aa": "bb"}));

        let error = apply(&mut value, Mutation::Delete, "/config/bar/qq", None, false)
            .expect_err("deleting a missing key is an error");
        assert_eq!(error.status, StatusCode::NOT_FOUND);

        apply(
            &mut value,
            Mutation::Post,
            "/config/list",
            Some(json!("e")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["list"], json!(["a", "b", "c", "e"]));

        apply(
            &mut value,
            Mutation::Put,
            "/config/list/3",
            Some(json!("d")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["list"], json!(["a", "b", "c", "d", "e"]));

        apply(&mut value, Mutation::Delete, "/config/list/3", None, false).unwrap();
        assert_eq!(value["config"]["list"], json!(["a", "b", "c", "e"]));

        apply(
            &mut value,
            Mutation::Patch,
            "/config/list/3",
            Some(json!("d")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["list"], json!(["a", "b", "c", "d"]));

        apply(
            &mut value,
            Mutation::Post,
            "/config/list",
            Some(json!(["e", "f", "g"])),
            true,
        )
        .unwrap();
        assert_eq!(
            value["config"]["list"],
            json!(["a", "b", "c", "d", "e", "f", "g"])
        );
    }

    #[test]
    fn put_inserts_and_creates_parent_objects() {
        let mut value = wrapper();
        apply(
            &mut value,
            Mutation::Put,
            "/config/created/nested",
            Some(json!(1)),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["created"]["nested"], json!(1));

        apply(
            &mut value,
            Mutation::Put,
            "/config/list/0",
            Some(json!("z")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["list"], json!(["z", "a", "b", "c"]));

        let error = apply(
            &mut value,
            Mutation::Put,
            "/config/foo",
            Some(json!("x")),
            false,
        )
        .expect_err("PUT on an existing key conflicts");
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[test]
    fn patch_missing_key_is_not_found() {
        let mut value = wrapper();
        let error = apply(
            &mut value,
            Mutation::Patch,
            "/config/missing",
            Some(json!(1)),
            false,
        )
        .expect_err("PATCH on a missing key is 404");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn array_index_bounds_and_canonical_form() {
        let mut value = wrapper();
        assert!(apply(
            &mut value,
            Mutation::Patch,
            "/config/list/9",
            Some(json!("x")),
            false
        )
        .is_err());
        assert!(apply(
            &mut value,
            Mutation::Put,
            "/config/list/01",
            Some(json!("x")),
            false
        )
        .is_err());
        // PUT may append at len.
        apply(
            &mut value,
            Mutation::Put,
            "/config/list/3",
            Some(json!("d")),
            false,
        )
        .unwrap();
        assert_eq!(value["config"]["list"], json!(["a", "b", "c", "d"]));
    }

    #[test]
    fn ellipsis_requires_array_payload() {
        let mut value = wrapper();
        let error = apply(
            &mut value,
            Mutation::Post,
            "/config/list",
            Some(json!("not-an-array")),
            true,
        )
        .expect_err("... needs an array payload");
        assert!(error.message.contains("final element is not an array"));
    }

    #[test]
    fn root_operations_use_the_config_wrapper() {
        let mut value = wrapper();
        apply(
            &mut value,
            Mutation::Post,
            "/config/",
            Some(json!({"apps": {}})),
            false,
        )
        .unwrap();
        assert_eq!(value["config"], json!({"apps": {}}));

        let error = apply(
            &mut value,
            Mutation::Put,
            "/config/",
            Some(json!({"apps": {}})),
            false,
        )
        .expect_err("PUT on /config/ conflicts with the existing wrapper key");
        assert_eq!(error.status, StatusCode::CONFLICT);

        apply(&mut value, Mutation::Delete, "/config/", None, false).unwrap();
        assert!(value.get("config").is_none());
    }

    #[test]
    fn indexes_ids_recursively_and_rejects_duplicates() {
        let value = json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "@id": "server",
                            "routes": [
                                {"@id": "outer", "handle": [{"handler": "subroute", "routes": [
                                    {"@id": "inner", "handle": []}
                                ]}]}
                            ]
                        }
                    }
                }
            }
        });
        let index = index_config(&value).unwrap();
        assert_eq!(
            index.get("inner").unwrap(),
            &vec![
                "apps".to_string(),
                "http".to_string(),
                "servers".to_string(),
                "srv0".to_string(),
                "routes".to_string(),
                "0".to_string(),
                "handle".to_string(),
                "0".to_string(),
                "routes".to_string(),
                "0".to_string(),
            ]
        );
        assert_eq!(
            display_path(index.get("outer").unwrap()),
            "/config/apps/http/servers/srv0/routes/0"
        );

        let duplicate = json!({
            "a": {"@id": "x"},
            "b": {"@id": "x"}
        });
        let error = index_config(&duplicate).unwrap_err();
        assert!(error.contains("duplicate ID 'x'"), "{error}");

        let invalid = json!({"a": {"@id": true}});
        let error = index_config(&invalid).unwrap_err();
        assert!(
            error.contains("@id field must be a string or number"),
            "{error}"
        );
    }

    #[test]
    fn numeric_ids_are_indexed() {
        let value = json!({"a": {"@id": 42}});
        let index = index_config(&value).unwrap();
        assert_eq!(index.get("42").unwrap(), &vec!["a".to_string()]);
    }
}
