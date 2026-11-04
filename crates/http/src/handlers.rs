//! Built-in HTTP handlers for the supported Caddy module set.
//!
//! Handler values that Caddy expands through the request replacer are expanded here with the
//! request-scoped [`crate::placeholders::Replacer`] (T-ROUTE-030/T-ROUTE-031):
//!
//! * `static_response` body and header names/values use `ReplaceKnown` semantics (unknown
//!   placeholders stay visible), matching Caddy's `modules/caddyhttp/staticresp.go`.
//! * `headers` request/response names and values use `ReplaceKnown` semantics, matching
//!   `modules/caddyhttp/headers/headers.go`.
//! * `rewrite` covers Caddy's full field set: `method`, `uri`, `strip_path_prefix`,
//!   `strip_path_suffix`, `uri_substring`, `path_regexp` and `query` operations in Caddy's order.
//!   Placeholders use `ReplaceAll` for the setters/strippers/substring replacer and
//!   `ReplaceKnown` for query replacements, matching `modules/caddyhttp/rewrite/rewrite.go`;
//!   `path_regexp`/`query.replace` capture expansion uses Go `$N` syntax. `vars` keys/values use
//!   `ReplaceAll`, matching `modules/caddyhttp/vars.go`.
//! * `request_body` supports Caddy's `max_size` (lazy `413` when a later handler reads past the
//!   limit) and experimental `set` (body replacement with `ReplaceKnown` placeholders), matching
//!   `modules/caddyhttp/requestbody/requestbody.go`.
//! * `map` supports Caddy's exact/regexp mappings, positional outputs, null outputs and defaults,
//!   publishing destination placeholders for later handlers (`modules/caddyhttp/map/map.go`).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};

use crate::matchers::percent_decode;
use crate::regex_lite::Regex;
use crate::router::Router;
use crate::types::{Error, Handler, Outcome, Request, Response, Result, StreamingOutcome};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Convert a JSON value (string or array of strings) into header values.
pub fn header_values(value: &serde_json::Value, path: &str) -> Result<Vec<HeaderValue>> {
    header_value_strings(value, path)?
        .into_iter()
        .map(|item| {
            HeaderValue::from_str(&item)
                .map_err(|error| invalid(path, format!("invalid header value `{item}`: {error}")))
        })
        .collect()
}

/// Convert a JSON value (string or array of strings) into raw header value strings.
///
/// Expansion happens per request, so values are kept as strings until the handler runs.
fn header_value_strings(value: &serde_json::Value, path: &str) -> Result<Vec<String>> {
    let items: Vec<&str> = match value {
        serde_json::Value::String(value) => vec![value],
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| invalid(path, "header values must be strings"))
            })
            .collect::<Result<_>>()?,
        _ => {
            return Err(invalid(
                path,
                "header value must be a string or array of strings",
            ))
        }
    };
    Ok(items.into_iter().map(str::to_string).collect())
}

fn expand_header_name(request: &Request, name: &str, path: &str) -> Result<HeaderName> {
    let expanded = request.replace_known(name);
    expanded
        .parse::<HeaderName>()
        .map_err(|error| invalid(path, format!("invalid header name `{expanded}`: {error}")))
}

fn expand_header_values(
    request: &Request,
    values: &[String],
    path: &str,
) -> Result<Vec<HeaderValue>> {
    values
        .iter()
        .map(|value| {
            let expanded = request.replace_known(value);
            HeaderValue::from_str(&expanded).map_err(|error| {
                invalid(path, format!("invalid header value `{expanded}`: {error}"))
            })
        })
        .collect()
}

/// `static_response`: write a fixed response, expanding placeholders in body and headers.
pub struct StaticResponseHandler {
    status: StatusCode,
    headers: Vec<(String, Vec<String>)>,
    body: String,
}

impl StaticResponseHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "static_response must be an object"))?;
        let status = match object.get("status_code") {
            Some(serde_json::Value::Number(number)) => number
                .as_u64()
                .and_then(|code| u16::try_from(code).ok())
                .and_then(|code| StatusCode::from_u16(code).ok())
                .ok_or_else(|| invalid(path, "`status_code` is not a valid HTTP status"))?,
            Some(serde_json::Value::String(text)) => text
                .parse::<u16>()
                .ok()
                .and_then(|code| StatusCode::from_u16(code).ok())
                .ok_or_else(|| invalid(path, "`status_code` is not a valid HTTP status"))?,
            Some(_) => return Err(invalid(path, "`status_code` must be a number")),
            None => StatusCode::OK,
        };
        let body = object
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut headers = Vec::new();
        if let Some(values) = object.get("headers") {
            let values = values
                .as_object()
                .ok_or_else(|| invalid(path, "`headers` must be an object"))?;
            for (field, value) in values {
                headers.push((
                    field.clone(),
                    header_value_strings(value, &format!("{path}.headers.{field}"))?,
                ));
            }
        }
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

/// Caddy's implicit `Content-Type` for a `static_response` body.
///
/// Mirrors `modules/caddyhttp/staticresp.go`: a body that (after trimming whitespace) is at least
/// three bytes long, starts/ends with `{`/`}` or `[`/`]`, and is valid JSON is served as
/// `application/json`; every other non-empty body is `text/plain; charset=utf-8`.
fn implicit_content_type(body: &str) -> &'static str {
    let trimmed = body.trim();
    if trimmed.len() > 2 {
        let bytes = trimmed.as_bytes();
        let braced = bytes[0] == b'{' && bytes[bytes.len() - 1] == b'}';
        let bracketed = bytes[0] == b'[' && bytes[bytes.len() - 1] == b']';
        if (braced || bracketed) && serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return "application/json";
        }
    }
    "text/plain; charset=utf-8"
}

/// Caddy only fills in an implicit `Content-Type` when the configured headers left it absent or
/// empty (`w.Header().Get("Content-Type") == ""`); an explicit non-empty value always wins.
fn implicit_content_type_is_unset(headers: &http::HeaderMap) -> bool {
    match headers.get(http::header::CONTENT_TYPE) {
        None => true,
        Some(value) => value.is_empty(),
    }
}

#[async_trait]
impl Handler for StaticResponseHandler {
    fn name(&self) -> &'static str {
        "static_response"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let body = request.replace_known(&self.body);
        // Caddy sets the implicit Content-Type from the *expanded* body, on GET and HEAD alike;
        // the body itself is discarded by the transport for HEAD, never the headers.
        let implicit_type = if body.is_empty() {
            None
        } else {
            Some(implicit_content_type(&body))
        };
        let mut response = Response {
            status: self.status,
            headers: http::HeaderMap::new(),
            body: Bytes::from(body),
        };
        for (raw_name, values) in &self.headers {
            let path = format!("static_response.headers.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            for value in values {
                response.headers.append(name.clone(), value);
            }
        }
        if let Some(content_type) = implicit_type {
            if implicit_content_type_is_unset(&response.headers) {
                response.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(content_type),
                );
            }
        }
        Ok(Outcome::Respond(response))
    }
}

/// `headers`: stage response header mutations (and apply request header mutations).
pub struct HeadersHandler {
    request_set: Vec<(String, Vec<String>)>,
    response_set: Vec<(String, Vec<String>)>,
    response_add: Vec<(String, Vec<String>)>,
    response_delete: Vec<String>,
}

impl HeadersHandler {
    /// Build from Caddy JSON (`{"handler":"headers","response":{...}}`).
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "headers handler must be an object"))?;
        let mut handler = Self {
            request_set: Vec::new(),
            response_set: Vec::new(),
            response_add: Vec::new(),
            response_delete: Vec::new(),
        };
        if let Some(request) = object.get("request") {
            handler.request_set = parse_header_operations(request, &format!("{path}.request"))?;
        }
        if let Some(response) = object.get("response") {
            let response_path = format!("{path}.response");
            let response_object = response
                .as_object()
                .ok_or_else(|| invalid(&response_path, "response must be an object"))?;
            if let Some(set) = response_object.get("set") {
                handler.response_set = parse_header_map(set, &format!("{response_path}.set"))?;
            }
            if let Some(add) = response_object.get("add") {
                handler.response_add = parse_header_map(add, &format!("{response_path}.add"))?;
            }
            if let Some(delete) = response_object.get("delete") {
                let delete = delete.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{response_path}.delete"),
                        "delete must be an array",
                    )
                })?;
                for (index, field) in delete.iter().enumerate() {
                    let field = field.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{response_path}.delete[{index}]"),
                            "expected a string",
                        )
                    })?;
                    handler.response_delete.push(field.to_string());
                }
            }
        }
        Ok(handler)
    }
}

fn parse_header_map(value: &serde_json::Value, path: &str) -> Result<Vec<(String, Vec<String>)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    let mut output = Vec::new();
    for (field, value) in object {
        output.push((
            field.clone(),
            header_value_strings(value, &format!("{path}.{field}"))?,
        ));
    }
    Ok(output)
}

fn parse_header_operations(
    value: &serde_json::Value,
    path: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    if let Some(set) = object.get("set") {
        parse_header_map(set, &format!("{path}.set"))
    } else {
        Ok(Vec::new())
    }
}

#[async_trait]
impl Handler for HeadersHandler {
    fn name(&self) -> &'static str {
        "headers"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        for (raw_name, values) in &self.request_set {
            let path = format!("headers.request.set.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            request.headers.remove(&name);
            for value in values {
                request.headers.append(name.clone(), value);
            }
        }
        for (raw_name, values) in &self.response_set {
            let path = format!("headers.response.set.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            request.pending_response_headers.remove(&name);
            for value in values {
                request.pending_response_headers.append(name.clone(), value);
            }
        }
        for (raw_name, values) in &self.response_add {
            let path = format!("headers.response.add.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            for value in values {
                request.pending_response_headers.append(name.clone(), value);
            }
        }
        for raw_name in &self.response_delete {
            let name = expand_header_name(&request, raw_name, "headers.response.delete")?;
            request.pending_response_headers.remove(&name);
        }
        Ok(Outcome::Continue(request))
    }
}

/// `vars`: set request variables, expanding placeholders in names and values.
pub struct VarsHandler {
    vars: Vec<(String, String)>,
}

impl VarsHandler {
    /// Build from Caddy JSON; every string field except `handler` is a variable.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "vars handler must be an object"))?;
        let mut vars = Vec::new();
        for (key, value) in object {
            if key == "handler" {
                continue;
            }
            let value = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::Bool(flag) => flag.to_string(),
                _ => continue,
            };
            vars.push((key.clone(), value));
        }
        Ok(Self { vars })
    }
}

#[async_trait]
impl Handler for VarsHandler {
    fn name(&self) -> &'static str {
        "vars"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let vars: Vec<(String, String)> = self
            .vars
            .iter()
            .map(|(key, value)| (request.replace_all(key), request.replace_all(value)))
            .collect();
        for (key, value) in vars {
            request.vars.insert(key, value);
        }
        Ok(Outcome::Continue(request))
    }
}

/// One `uri_substring` replacement (Caddy's `substrReplacer`).
#[derive(Debug, Clone)]
struct UriSubstring {
    find: String,
    replace: String,
    /// `limit <= 0` means unlimited (Caddy's sentinel).
    limit: i64,
}

/// One `path_regexp` replacement (Caddy's `regexReplacer`).
#[derive(Debug)]
struct PathRegexp {
    replace: String,
    regex: Regex,
}

/// One `query` add/set/rename argument (`key`/`val`).
#[derive(Debug, Clone, Default)]
struct QueryArgument {
    key: String,
    val: String,
}

/// One `query.replace` operation.
#[derive(Debug)]
struct QueryReplacement {
    key: String,
    search: String,
    replace: String,
    regex: Option<Regex>,
}

/// Caddy's `queryOps`: rename, set, add, replace and delete query parameters in that order.
#[derive(Debug, Default)]
struct QueryOps {
    rename: Vec<QueryArgument>,
    set: Vec<QueryArgument>,
    add: Vec<QueryArgument>,
    replace: Vec<QueryReplacement>,
    delete: Vec<String>,
}

/// `rewrite`: change the request URI, method, or path (Caddy's `http.handlers.rewrite`).
///
/// Order of operations matches Caddy's `Rewrite.Rewrite`: `method`, `uri`, `strip_path_prefix`,
/// `strip_path_suffix`, `uri_substring` entries, `path_regexp` entries, then `query` operations.
///
/// Expansion/validation follows Caddy: `method`/`uri`/prefix/suffix and `uri_substring`
/// find/replace use `ReplaceAll` semantics; `path_regexp` replaces are expanded first and then use
/// Go-style `$N` capture expansion; `query.replace` search/replace use `ReplaceKnown` semantics
/// (Caddy's code calls `ReplaceKnown` there). Unknown or malformed fields fail loudly.
#[derive(Debug)]
pub struct RewriteHandler {
    uri: Option<String>,
    method: Option<String>,
    strip_path_prefix: Option<String>,
    strip_path_suffix: Option<String>,
    uri_substring: Vec<UriSubstring>,
    path_regexp: Vec<PathRegexp>,
    query: Option<QueryOps>,
}

impl RewriteHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "rewrite handler must be an object"))?;
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "handler"
                    | "uri"
                    | "method"
                    | "strip_path_prefix"
                    | "strip_path_suffix"
                    | "uri_substring"
                    | "path_regexp"
                    | "query"
            ) {
                return Err(invalid(
                    &format!("{path}.{field}"),
                    format!("unsupported rewrite field `{field}`"),
                ));
            }
        }
        let uri = optional_string(object, "uri", path)?;
        let method = optional_string(object, "method", path)?;
        let strip_path_prefix = optional_string(object, "strip_path_prefix", path)?;
        let strip_path_suffix = optional_string(object, "strip_path_suffix", path)?;
        let uri_substring = parse_uri_substring(object, path)?;
        let path_regexp = parse_path_regexp(object, path)?;
        let query = parse_query_ops(object, path)?;
        Ok(Self {
            uri,
            method,
            strip_path_prefix,
            strip_path_suffix,
            uri_substring,
            path_regexp,
            query,
        })
    }
}

fn optional_string(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    path: &str,
) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(
            &format!("{path}.{field}"),
            format!("`{field}` must be a string"),
        )),
    }
}

fn parse_uri_substring(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<Vec<UriSubstring>> {
    let Some(value) = object.get("uri_substring") else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or_else(|| {
        invalid(
            &format!("{path}.uri_substring"),
            "`uri_substring` must be an array",
        )
    })?;
    let mut replacements = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}.uri_substring[{index}]");
        let item = item
            .as_object()
            .ok_or_else(|| invalid(&item_path, "uri_substring entry must be an object"))?;
        for field in item.keys() {
            if !matches!(field.as_str(), "find" | "replace" | "limit") {
                return Err(invalid(
                    &format!("{item_path}.{field}"),
                    format!("unsupported uri_substring field `{field}`"),
                ));
            }
        }
        let find = optional_string(item, "find", &item_path)?.unwrap_or_default();
        let replace = optional_string(item, "replace", &item_path)?.unwrap_or_default();
        let limit = match item.get("limit") {
            None | Some(serde_json::Value::Null) => 0,
            Some(serde_json::Value::Number(number)) => number.as_i64().ok_or_else(|| {
                invalid(&format!("{item_path}.limit"), "`limit` must be an integer")
            })?,
            Some(_) => {
                return Err(invalid(
                    &format!("{item_path}.limit"),
                    "`limit` must be an integer",
                ))
            }
        };
        replacements.push(UriSubstring {
            find,
            replace,
            limit,
        });
    }
    Ok(replacements)
}

fn parse_path_regexp(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<Vec<PathRegexp>> {
    let Some(value) = object.get("path_regexp") else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or_else(|| {
        invalid(
            &format!("{path}.path_regexp"),
            "`path_regexp` must be an array",
        )
    })?;
    let mut replacements = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}.path_regexp[{index}]");
        let item = item
            .as_object()
            .ok_or_else(|| invalid(&item_path, "path_regexp entry must be an object"))?;
        for field in item.keys() {
            if !matches!(field.as_str(), "find" | "replace") {
                return Err(invalid(
                    &format!("{item_path}.{field}"),
                    format!("unsupported path_regexp field `{field}`"),
                ));
            }
        }
        let find = optional_string(item, "find", &item_path)?.unwrap_or_default();
        if find.is_empty() {
            return Err(invalid(
                &format!("{item_path}.find"),
                "path_regexp `find` must not be empty",
            ));
        }
        let replace = optional_string(item, "replace", &item_path)?.unwrap_or_default();
        let regex = Regex::new(&find).map_err(|error| match error {
            Error::InvalidConfig { message, .. } => Error::InvalidConfig {
                path: format!("{item_path}.find"),
                message,
            },
            other => other,
        })?;
        replacements.push(PathRegexp { replace, regex });
    }
    Ok(replacements)
}

fn parse_query_arguments(value: &serde_json::Value, path: &str) -> Result<Vec<QueryArgument>> {
    let items = value.as_array().ok_or_else(|| {
        invalid(
            path,
            "query operation must be an array of {key, val} objects",
        )
    })?;
    let mut arguments = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let item = item
            .as_object()
            .ok_or_else(|| invalid(&item_path, "query operation entry must be an object"))?;
        for field in item.keys() {
            if !matches!(field.as_str(), "key" | "val") {
                return Err(invalid(
                    &format!("{item_path}.{field}"),
                    format!("unsupported query operation field `{field}`"),
                ));
            }
        }
        arguments.push(QueryArgument {
            key: optional_string(item, "key", &item_path)?.unwrap_or_default(),
            val: optional_string(item, "val", &item_path)?.unwrap_or_default(),
        });
    }
    Ok(arguments)
}

fn parse_query_ops(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<Option<QueryOps>> {
    let Some(value) = object.get("query") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let query_path = format!("{path}.query");
    let query = value
        .as_object()
        .ok_or_else(|| invalid(&query_path, "`query` must be an object"))?;
    for field in query.keys() {
        if !matches!(
            field.as_str(),
            "rename" | "set" | "add" | "replace" | "delete"
        ) {
            return Err(invalid(
                &format!("{query_path}.{field}"),
                format!("unsupported query operation `{field}`"),
            ));
        }
    }
    let mut ops = QueryOps::default();
    if let Some(value) = query.get("rename") {
        ops.rename = parse_query_arguments(value, &format!("{query_path}.rename"))?;
    }
    if let Some(value) = query.get("set") {
        ops.set = parse_query_arguments(value, &format!("{query_path}.set"))?;
    }
    if let Some(value) = query.get("add") {
        ops.add = parse_query_arguments(value, &format!("{query_path}.add"))?;
    }
    if let Some(value) = query.get("delete") {
        let items = value.as_array().ok_or_else(|| {
            invalid(
                &format!("{query_path}.delete"),
                "`delete` must be an array of strings",
            )
        })?;
        let mut deletes = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let item = item.as_str().ok_or_else(|| {
                invalid(
                    &format!("{query_path}.delete[{index}]"),
                    "`delete` entries must be strings",
                )
            })?;
            deletes.push(item.to_string());
        }
        ops.delete = deletes;
    }
    if let Some(value) = query.get("replace") {
        let items = value.as_array().ok_or_else(|| {
            invalid(
                &format!("{query_path}.replace"),
                "`replace` must be an array",
            )
        })?;
        for (index, item) in items.iter().enumerate() {
            let item_path = format!("{query_path}.replace[{index}]");
            let item = item
                .as_object()
                .ok_or_else(|| invalid(&item_path, "query replace entry must be an object"))?;
            for field in item.keys() {
                if !matches!(
                    field.as_str(),
                    "key" | "search" | "search_regexp" | "replace"
                ) {
                    return Err(invalid(
                        &format!("{item_path}.{field}"),
                        format!("unsupported query replace field `{field}`"),
                    ));
                }
            }
            let key = optional_string(item, "key", &item_path)?.unwrap_or_default();
            let search = optional_string(item, "search", &item_path)?.unwrap_or_default();
            let search_regexp = optional_string(item, "search_regexp", &item_path)?;
            let replace = optional_string(item, "replace", &item_path)?.unwrap_or_default();
            let regex = match search_regexp.as_deref() {
                Some(pattern) if !pattern.is_empty() => {
                    Some(Regex::new(pattern).map_err(|error| match error {
                        Error::InvalidConfig { message, .. } => Error::InvalidConfig {
                            path: format!("{item_path}.search_regexp"),
                            message,
                        },
                        other => other,
                    })?)
                }
                _ => None,
            };
            ops.replace.push(QueryReplacement {
                key,
                search,
                replace,
                regex,
            });
        }
    }
    Ok(Some(ops))
}

/// Apply a rewritten `uri` template with Caddy's component-wise semantics: a configured URI that
/// has no `?` preserves the current query string, and a URI with only `?query` preserves the
/// current path. Fragments are dropped because they are never sent to a server.
fn rewritten_uri(request: &Request, template: &str) -> Result<Uri> {
    let expanded = request.replace_all(template);
    let without_fragment = expanded.split('#').next().unwrap_or("");
    let (path, query) = match without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (without_fragment, None),
    };

    let mut new_path = request.uri.path().to_string();
    let mut new_query = request.uri.query().map(str::to_string);
    if !path.is_empty() {
        new_path = path.to_string();
    }
    if let Some(query) = query {
        new_query = if query.is_empty() {
            None
        } else {
            Some(query.to_string())
        };
    }

    let mut rebuilt = new_path;
    if let Some(query) = &new_query {
        rebuilt.push('?');
        rebuilt.push_str(query);
    }
    rebuilt
        .parse::<Uri>()
        .map_err(|error| invalid("rewrite.uri", error.to_string()))
}

/// Replace the request URI's path (keeping the current query string).
fn set_uri_path(request: &mut Request, path: &str, context: &str) -> Result<()> {
    let mut rebuilt = path.to_string();
    if let Some(query) = request.uri.query() {
        rebuilt.push('?');
        rebuilt.push_str(query);
    }
    request.uri = rebuilt
        .parse::<Uri>()
        .map_err(|error| invalid(context, error.to_string()))?;
    Ok(())
}

/// Replace the request URI's path and (optional) query string.
fn set_uri_path_query(
    request: &mut Request,
    path: &str,
    query: Option<&str>,
    context: &str,
) -> Result<()> {
    let mut rebuilt = path.to_string();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        rebuilt.push('?');
        rebuilt.push_str(query);
    }
    request.uri = rebuilt
        .parse::<Uri>()
        .map_err(|error| invalid(context, error.to_string()))?;
    Ok(())
}

fn strip_path_prefix(request: &mut Request, prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let mut prefix = prefix.to_string();
    if !prefix.starts_with('/') {
        prefix.insert(0, '/');
    }
    let Some(rest) = request.uri.path().strip_prefix(prefix.as_str()) else {
        return Ok(());
    };
    let rest = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        // Caddy's `canonicalizePath` restores the leading slash after trimming.
        format!("/{rest}")
    };
    set_uri_path(request, &rest, "rewrite.strip_path_prefix")
}

fn strip_path_suffix(request: &mut Request, suffix: &str) -> Result<()> {
    if suffix.is_empty() {
        return Ok(());
    }
    let path = request.uri.path().to_string();
    if path.len() < suffix.len() {
        return Ok(());
    }
    let start = path.len() - suffix.len();
    if !path.is_char_boundary(start) || !path[start..].eq_ignore_ascii_case(suffix) {
        return Ok(());
    }
    let trimmed = &path[..start];
    let canonical = if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    set_uri_path(request, &canonical, "rewrite.strip_path_suffix")
}

/// Go `strings.Replace`-style replacement. An empty `find` inserts `replace` before each UTF-8
/// rune and at the end (Go's `strings.ReplaceAll(s, "", new)` behaviour).
fn replace_occurrences(
    haystack: &str,
    find: &str,
    replacement: &str,
    limit: Option<usize>,
) -> String {
    if find.is_empty() {
        let mut output = String::with_capacity(haystack.len() + replacement.len());
        let mut count = 0;
        for character in haystack.chars() {
            if limit.is_none_or(|limit| count < limit) {
                output.push_str(replacement);
                count += 1;
            }
            output.push(character);
        }
        if limit.is_none_or(|limit| count < limit) {
            output.push_str(replacement);
        }
        return output;
    }
    let mut output = String::with_capacity(haystack.len());
    let mut rest = haystack;
    let mut count = 0;
    while limit.is_none_or(|limit| count < limit) {
        let Some(position) = rest.find(find) else {
            break;
        };
        output.push_str(&rest[..position]);
        output.push_str(replacement);
        rest = &rest[position + find.len()..];
        count += 1;
    }
    output.push_str(rest);
    output
}

/// Apply one `uri_substring` operation to both the path and the query (Caddy's `substrReplacer`).
fn apply_uri_substring(request: &mut Request, substring: &UriSubstring) -> Result<()> {
    if substring.find.is_empty() {
        return Ok(());
    }
    let find = request.replace_all(&substring.find);
    let replacement = request.replace_all(&substring.replace);
    // Caddy checks the configured `find` for emptiness before expansion; an expansion that
    // becomes empty is still passed to strings.Replace, which inserts the replacement everywhere.
    let limit = Some(substring.limit)
        .filter(|limit| *limit > 0)
        .map(|limit| limit as usize);
    let path = request.uri.path().to_string();
    let new_path = replace_occurrences(&path, &find, &replacement, limit);
    let new_query = request
        .uri
        .query()
        .map(|query| replace_occurrences(query, &find, &replacement, limit));
    if new_path == path && new_query.as_deref() == request.uri.query() {
        return Ok(());
    }
    set_uri_path_query(
        request,
        &new_path,
        new_query.as_deref(),
        "rewrite.uri_substring",
    )
}

/// Apply one `path_regexp` operation to the URI path (Caddy's `regexReplacer`).
fn apply_path_regexp(request: &mut Request, regexp: &PathRegexp) -> Result<()> {
    let template = request.replace_all(&regexp.replace);
    let path = request.uri.path().to_string();
    let new_path = regexp.regex.replace_all(&path, &template);
    if new_path == path {
        return Ok(());
    }
    set_uri_path(request, &new_path, "rewrite.path_regexp")
}

fn query_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~') {
            escaped.push(character);
        } else if character == ' ' {
            escaped.push('+');
        } else {
            let mut buffer = [0_u8; 4];
            for byte in character.encode_utf8(&mut buffer).bytes() {
                escaped.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    escaped
}

fn parse_query(raw: &str) -> BTreeMap<String, Vec<String>> {
    let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query
            .entry(percent_decode(&key.replace('+', " ")))
            .or_default()
            .push(percent_decode(&value.replace('+', " ")));
    }
    query
}

fn encode_query(query: &BTreeMap<String, Vec<String>>) -> String {
    let mut pairs = Vec::new();
    for (key, values) in query {
        for value in values {
            pairs.push(format!("{}={}", query_escape(key), query_escape(value)));
        }
    }
    pairs.join("&")
}

fn replace_query_value(
    value: &str,
    search: &str,
    replacement: &str,
    regex: Option<&Regex>,
) -> String {
    match regex {
        Some(regex) => regex.replace_all(value, replacement),
        None => replace_occurrences(value, search, replacement, None),
    }
}

/// Apply Caddy's `queryOps` in order: rename, set, add, replace, delete.
fn apply_query_ops(request: &mut Request, ops: &QueryOps) -> Result<()> {
    let raw = request.uri.query().unwrap_or("").to_string();
    let mut query = parse_query(&raw);

    for argument in &ops.rename {
        let key = request.replace_all(&argument.key);
        let val = request.replace_all(&argument.val);
        if key.is_empty() || val.is_empty() || key == val {
            continue;
        }
        if let Some(values) = query.remove(&key) {
            query.insert(val, values);
        }
    }
    for argument in &ops.set {
        let key = request.replace_all(&argument.key);
        if key.is_empty() {
            continue;
        }
        let val = request.replace_all(&argument.val);
        query.insert(key, vec![val]);
    }
    for argument in &ops.add {
        let key = request.replace_all(&argument.key);
        if key.is_empty() {
            continue;
        }
        let val = request.replace_all(&argument.val);
        query.entry(key).or_default().push(val);
    }
    for replacement in &ops.replace {
        let key = request.replace_all(&replacement.key);
        let search = request.replace_known(&replacement.search);
        let replace = request.replace_known(&replacement.replace);
        if key == "*" {
            for values in query.values_mut() {
                for value in values {
                    *value =
                        replace_query_value(value, &search, &replace, replacement.regex.as_ref());
                }
            }
        } else if let Some(values) = query.get_mut(&key) {
            for value in values {
                *value = replace_query_value(value, &search, &replace, replacement.regex.as_ref());
            }
        }
    }
    for delete in &ops.delete {
        let key = request.replace_all(delete);
        if !key.is_empty() {
            query.remove(&key);
        }
    }

    let encoded = encode_query(&query);
    let path = request.uri.path().to_string();
    let query = if encoded.is_empty() {
        None
    } else {
        Some(encoded.as_str())
    };
    set_uri_path_query(request, &path, query, "rewrite.query")
}

#[async_trait]
impl Handler for RewriteHandler {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        // Order matches Caddy's `Rewrite.Rewrite`.
        if let Some(method) = &self.method {
            let expanded = request.replace_all(method).to_ascii_uppercase();
            request.method = Method::from_bytes(expanded.as_bytes())
                .map_err(|_| invalid("rewrite.method", format!("invalid method `{expanded}`")))?;
        }
        if let Some(uri) = &self.uri {
            if !uri.is_empty() {
                request.uri = rewritten_uri(&request, uri)?;
            }
        }
        if let Some(prefix) = &self.strip_path_prefix {
            let expanded = request.replace_all(prefix);
            strip_path_prefix(&mut request, &expanded)?;
        }
        if let Some(suffix) = &self.strip_path_suffix {
            let expanded = request.replace_all(suffix);
            strip_path_suffix(&mut request, &expanded)?;
        }
        for substring in &self.uri_substring {
            apply_uri_substring(&mut request, substring)?;
        }
        for regexp in &self.path_regexp {
            apply_path_regexp(&mut request, regexp)?;
        }
        if let Some(query) = &self.query {
            apply_query_ops(&mut request, query)?;
        }
        Ok(Outcome::Continue(request))
    }
}

/// `subroute`: evaluate a nested route list.
pub struct SubrouteHandler {
    router: Arc<Router>,
}

impl SubrouteHandler {
    /// Build from a nested router.
    pub fn new(router: Router) -> Self {
        Self {
            router: Arc::new(router),
        }
    }
}

#[async_trait]
impl Handler for SubrouteHandler {
    fn name(&self) -> &'static str {
        "subroute"
    }

    fn requires_buffered_request_body(&self) -> bool {
        self.router.requires_buffered_request_body()
    }

    fn consumes_request_body(&self) -> bool {
        self.router.consumes_request_body()
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        // Caddy compiles a subroute's routes with the *outer* handler chain as their continuation
        // (`RouteList.Compile(next)`), so an empty or non-matching subroute is a no-op that passes
        // control on instead of responding. `handle_outcome` exposes exactly that distinction.
        self.router.handle_outcome(request).await
    }

    async fn handle_streaming(&self, request: Request) -> Result<StreamingOutcome> {
        // Preserve streamed inner responses (for example a reverse_proxy inside a subroute)
        // instead of collecting them at the subroute boundary.
        self.router.handle_streaming_outcome(request).await
    }
}

/// `encode`: accepted for configuration compatibility; compression is tracked for a later task.
pub struct EncodeHandler;

#[async_trait]
impl Handler for EncodeHandler {
    fn name(&self) -> &'static str {
        "encode"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        // The handler is a no-op rather than an error so configurations remain runnable; the
        // divergence is recorded in docs/compatibility/BEHAVIOR-DIVERGENCES.md (DIV-0009).
        Ok(Outcome::Continue(request))
    }
}

/// `request_body`: limit the request body size read by later handlers and/or replace it.
///
/// Mirrors Caddy's `http.handlers.request_body` (v2.11.7):
///
/// * `max_size` — maximum number of bytes a later handler may read from the body. Exceeding it is
///   a `413` error: the router enforces it just before dispatching to a body-consuming handler
///   (for a body the engine already buffered, for example when `reverse_proxy` is in the route
///   tree), and streamed bodies fail lazily with [`crate::body::BodyError::TooLarge`]. Handlers
///   that never read the body are unaffected, matching Caddy's lazy `MaxBytesReader` semantics.
///   The `413` response has an empty body and no content type, matching the Caddy v2.11.7 oracle.
///   Caddy's field is an `int64`; JSON numbers must be non-negative integers, `0`/absent means
///   unlimited.
/// * `set` — replace the request body with a string, expanding known placeholders
///   (`ReplaceKnown` semantics, unknown placeholders stay visible, matching Caddy's comment on
///   user-supplied bodies). `Content-Length` is updated to the replacement length.
///
/// Unknown fields are rejected loudly (this build's configuration policy), whereas Caddy's
/// default `encoding/json` decoding silently ignores them.
#[derive(Debug)]
pub struct RequestBodyHandler {
    max_size: Option<u64>,
    set: Option<String>,
}

impl RequestBodyHandler {
    /// Build from a `request_body` handler JSON value.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "request_body handler configuration must be an object"))?;
        let mut max_size = None;
        if let Some(field) = object.get("max_size") {
            let field_path = format!("{path}.max_size");
            let bytes = field.as_u64().ok_or_else(|| {
                invalid(
                    &field_path,
                    "must be a non-negative integer number of bytes",
                )
            })?;
            if bytes > i64::MAX as u64 {
                return Err(invalid(
                    &field_path,
                    "must fit in a signed 64-bit integer (Caddy's `max_size` is `int64`)",
                ));
            }
            // Caddy applies the limit only when `MaxSize > 0`; `0` means unlimited.
            if bytes > 0 {
                max_size = Some(bytes);
            }
        }
        let set = match object.get("set") {
            Some(serde_json::Value::String(set)) => Some(set.clone()),
            Some(_) => return Err(invalid(&format!("{path}.set"), "must be a string")),
            None => None,
        };
        for field in object.keys() {
            if !matches!(field.as_str(), "handler" | "max_size" | "set") {
                return Err(invalid(
                    &format!("{path}.{field}"),
                    format!("unsupported request_body field `{field}`"),
                ));
            }
        }
        Ok(Self { max_size, set })
    }
}

#[async_trait]
impl Handler for RequestBodyHandler {
    fn name(&self) -> &'static str {
        "request_body"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        if let Some(set) = &self.set {
            // `ReplaceKnown`: unknown placeholders stay visible so JSON bodies with braces are not
            // blanked.
            let replaced = request.replace_known(set);
            let body = Bytes::from(replaced);
            let length = body.len();
            request.set_body_bytes(body);
            if length == 0 {
                request.headers.remove(http::header::CONTENT_LENGTH);
            } else {
                request.headers.insert(
                    http::header::CONTENT_LENGTH,
                    HeaderValue::from_str(&length.to_string()).map_err(|error| {
                        invalid(
                            "request_body.set",
                            format!("cannot set Content-Length: {error}"),
                        )
                    })?,
                );
            }
        }
        if let Some(max_size) = self.max_size {
            // Streaming bodies fail lazily when read; for buffered bodies the router enforces the
            // limit before the next body-consuming handler runs (matching Caddy's lazy
            // `MaxBytesReader` semantics: a handler that never reads the body is unaffected).
            request.limit_body(max_size);
        }
        Ok(Outcome::Continue(request))
    }
}

/// One scalar value in a `map` mapping output or default (Caddy's `any` JSON values).
#[derive(Debug, Clone, PartialEq)]
enum MapValue {
    Null,
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
}

impl MapValue {
    fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::String(value) => Ok(Self::String(value.clone())),
            serde_json::Value::Bool(value) => Ok(Self::Bool(*value)),
            serde_json::Value::Number(number) => {
                if let Some(integer) = number.as_i64() {
                    Ok(Self::Integer(integer))
                } else if let Some(float) = number.as_f64() {
                    Ok(Self::Float(float))
                } else {
                    Err(invalid(path, "map number is not representable"))
                }
            }
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err(invalid(
                path,
                "map outputs/defaults must be strings, numbers, booleans or null",
            )),
        }
    }

    /// Caddy's `caddy.ToString`: `None` for null (the output is treated as not mapped).
    fn render(&self) -> Option<String> {
        match self {
            Self::Null => None,
            Self::String(value) => Some(value.clone()),
            Self::Integer(value) => Some(value.to_string()),
            Self::Float(value) => Some(render_float(*value)),
            Self::Bool(value) => Some(value.to_string()),
        }
    }
}

/// Go's `fmt.Sprint` style float rendering (`1.0` prints as `1`, `1.5` as `1.5`).
fn render_float(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e18 {
        (value as i64).to_string()
    } else {
        value.to_string()
    }
}

/// One `map` mapping: an exact input or an input regular expression, plus positional outputs.
#[derive(Debug)]
struct MapMapping {
    input: String,
    regex: Option<Regex>,
    outputs: Vec<MapValue>,
}

/// `map`: map a source placeholder value to destination placeholders (Caddy's `http.handlers.map`).
///
/// Supported JSON: `source`, `destinations`, `mappings` (`input` or `input_regexp`, `outputs`)
/// and `defaults`. Mappings are evaluated in order for each destination; a null output is skipped;
/// a matching non-null output wins immediately; otherwise the positional default is used and an
/// absent default leaves the destination placeholder empty (Caddy's nil value).
///
/// Caddy evaluates mappings lazily when a destination placeholder is first used; this engine
/// evaluates them when the handler runs, which is observationally equivalent unless a later
/// handler changes request state that the source depends on before using a destination.
#[derive(Debug)]
pub struct MapHandler {
    source: String,
    destinations: Vec<String>,
    mappings: Vec<MapMapping>,
    defaults: Vec<MapValue>,
}

impl MapHandler {
    /// Build from a `map` handler JSON value.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "map handler configuration must be an object"))?;
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "handler" | "source" | "destinations" | "mappings" | "defaults"
            ) {
                return Err(invalid(
                    &format!("{path}.{field}"),
                    format!("unsupported map field `{field}`"),
                ));
            }
        }
        let source = match object.get("source") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(source)) => source.clone(),
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.source"),
                    "`source` must be a string",
                ))
            }
        };
        let destinations = match object.get("destinations") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => {
                let mut names = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let item_path = format!("{path}.destinations[{index}]");
                    let destination = item.as_str().ok_or_else(|| {
                        invalid(&item_path, "destination must be a placeholder string")
                    })?;
                    names.push(parse_destination(destination, &item_path)?);
                }
                names
            }
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.destinations"),
                    "`destinations` must be an array of placeholders",
                ))
            }
        };
        let mappings = match object.get("mappings") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => {
                let mut mappings = Vec::with_capacity(items.len());
                let mut seen_inputs: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                let mut seen_regexps: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for (index, item) in items.iter().enumerate() {
                    let mapping_path = format!("{path}.mappings[{index}]");
                    let mapping = parse_map_mapping(
                        item,
                        &mapping_path,
                        destinations.len(),
                        &mut seen_inputs,
                        &mut seen_regexps,
                    )?;
                    mappings.push(mapping);
                }
                mappings
            }
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.mappings"),
                    "`mappings` must be an array",
                ))
            }
        };
        let defaults = match object.get("defaults") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    MapValue::from_json(item, &format!("{path}.defaults[{index}]"))
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.defaults"),
                    "`defaults` must be an array",
                ))
            }
        };
        if !defaults.is_empty() && defaults.len() != destinations.len() {
            return Err(invalid(
                &format!("{path}.defaults"),
                format!(
                    "{} destinations != {} defaults",
                    destinations.len(),
                    defaults.len()
                ),
            ));
        }
        Ok(Self {
            source,
            destinations,
            mappings,
            defaults,
        })
    }

    fn resolve(&self, index: usize, input: &str, request: &Request) -> String {
        for mapping in &self.mappings {
            let Some(output) = mapping.outputs[index].render() else {
                continue;
            };
            match &mapping.regex {
                Some(regex) => {
                    if let Some(captures) = regex.captures(input) {
                        // Caddy returns the expanded regexp result directly (it is not run through
                        // the placeholder replacer on this path).
                        return regex.expand(&output, input, &captures);
                    }
                }
                None => {
                    if input == mapping.input {
                        return request.replace_all(&output);
                    }
                }
            }
        }
        match self.defaults.get(index).and_then(MapValue::render) {
            Some(default) => request.replace_all(&default),
            // Caddy returns a known-but-nil value; the placeholder expands to empty.
            None => String::new(),
        }
    }
}

/// Validate a map destination is exactly one placeholder and return its name.
fn parse_destination(destination: &str, path: &str) -> Result<String> {
    let valid = destination.starts_with('{')
        && destination.ends_with('}')
        && destination.len() >= 3
        && !destination[1..destination.len() - 1].contains('{')
        && !destination[1..destination.len() - 1].contains('}');
    if !valid {
        return Err(invalid(
            path,
            format!(
                "destination must be a placeholder and only a placeholder, got `{destination}`"
            ),
        ));
    }
    Ok(destination[1..destination.len() - 1].to_string())
}

fn parse_map_mapping(
    value: &serde_json::Value,
    path: &str,
    destinations: usize,
    seen_inputs: &mut std::collections::BTreeSet<String>,
    seen_regexps: &mut std::collections::BTreeSet<String>,
) -> Result<MapMapping> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "map mapping must be an object"))?;
    for field in object.keys() {
        if !matches!(field.as_str(), "input" | "input_regexp" | "outputs") {
            return Err(invalid(
                &format!("{path}.{field}"),
                format!("unsupported map mapping field `{field}`"),
            ));
        }
    }
    let input = match object.get("input") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(input)) => input.clone(),
        Some(_) => {
            return Err(invalid(
                &format!("{path}.input"),
                "`input` must be a string",
            ))
        }
    };
    let input_regexp = match object.get("input_regexp") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(pattern)) => Some(pattern.clone()),
        Some(_) => {
            return Err(invalid(
                &format!("{path}.input_regexp"),
                "`input_regexp` must be a string",
            ))
        }
    };
    if input_regexp.is_some() && object.get("input").is_some_and(|value| !value.is_null()) {
        return Err(invalid(
            path,
            "mapping has both `input` and `input_regexp`, which is ambiguous",
        ));
    }
    let regex = match &input_regexp {
        None => {
            if !seen_inputs.insert(input.clone()) {
                return Err(invalid(
                    path,
                    format!("duplicate input `{input}` in map mappings"),
                ));
            }
            None
        }
        Some(pattern) => {
            if !seen_regexps.insert(pattern.clone()) {
                return Err(invalid(
                    path,
                    format!("duplicate input_regexp `{pattern}` in map mappings"),
                ));
            }
            Some(Regex::new(pattern).map_err(|error| match error {
                Error::InvalidConfig { message, .. } => Error::InvalidConfig {
                    path: format!("{path}.input_regexp"),
                    message,
                },
                other => other,
            })?)
        }
    };
    let outputs = match object.get("outputs") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| MapValue::from_json(item, &format!("{path}.outputs[{index}]")))
            .collect::<Result<Vec<_>>>()?,
        Some(_) => {
            return Err(invalid(
                &format!("{path}.outputs"),
                "`outputs` must be an array",
            ))
        }
    };
    if outputs.len() != destinations {
        return Err(invalid(
            path,
            format!(
                "mapping has {} outputs but there are {destinations} destinations defined",
                outputs.len()
            ),
        ));
    }
    Ok(MapMapping {
        input,
        regex,
        outputs,
    })
}

#[async_trait]
impl Handler for MapHandler {
    fn name(&self) -> &'static str {
        "map"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let input = request.replace_all(&self.source);
        let mut values = Vec::with_capacity(self.destinations.len());
        for index in 0..self.destinations.len() {
            values.push(self.resolve(index, &input, &request));
        }
        for (destination, value) in self.destinations.iter().zip(values) {
            request.vars.insert(destination.clone(), value);
        }
        Ok(Outcome::Continue(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request(method: Method, uri: &str) -> Request {
        let mut request = Request::new(method, uri.parse::<Uri>().unwrap());
        request.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("example.com:8080"),
        );
        request
    }

    fn request() -> Request {
        let mut request = Request::new(Method::GET, "/old/path?q=1".parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    #[tokio::test]
    async fn static_response_writes_status_body_and_headers() {
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "status_code": 418,
                "body": "teapot",
                "headers": {"X-Test": ["yes"]}
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Respond(response) = handler.handle(request()).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(response.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(response.body, Bytes::from_static(b"teapot"));
        assert_eq!(response.headers["x-test"], "yes");
    }

    #[tokio::test]
    async fn static_response_expands_body_header_values_and_header_names() {
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.method} {http.request.uri.path} {http.request.host}",
                "headers": {
                    "X-Method-{http.request.method}": ["{http.request.method}"],
                    "X-Query": ["q={http.request.uri.query}"],
                    "X-Unknown": ["{not.a.placeholder}"]
                }
            }),
            "handler",
        )
        .unwrap();
        let request = test_request(Method::POST, "/some/path?q=1");
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(
            response.body,
            Bytes::from_static(b"POST /some/path example.com")
        );
        assert_eq!(response.headers["x-method-post"], "POST");
        assert_eq!(response.headers["x-query"], "q=q=1");
        // ReplaceKnown keeps unknown placeholders visible instead of silently dropping them.
        assert_eq!(response.headers["x-unknown"], "{not.a.placeholder}");
    }

    #[tokio::test]
    async fn headers_handler_expands_request_and_response_values() {
        let handler = HeadersHandler::from_json(
            &serde_json::json!({
                "handler": "headers",
                "request": {"set": {"X-From": ["{http.request.method}"]}},
                "response": {
                    "set": {"X-Path": ["{http.request.uri.path}"]},
                    "add": {"Vary": ["Accept"]}
                }
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.headers["x-from"], "GET");
        assert_eq!(request.pending_response_headers["x-path"], "/old/path");
        assert_eq!(request.pending_response_headers["vary"], "Accept");
    }

    #[tokio::test]
    async fn headers_handler_stages_response_headers() {
        let handler = HeadersHandler::from_json(
            &serde_json::json!({
                "handler": "headers",
                "response": {"set": {"X-Frame-Options": ["DENY"]}, "add": {"Vary": ["Accept"]}}
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.pending_response_headers["x-frame-options"], "DENY");
        assert_eq!(request.pending_response_headers["vary"], "Accept");
    }

    #[tokio::test]
    async fn rewrite_handler_strips_prefix_and_keeps_query() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "strip_path_prefix": "/old"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_expands_uri_placeholders_and_preserves_query() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "/new/{http.request.method}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/new/GET");
        // No `?` in the configured URI, so the original query string survives.
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_uri_with_only_query_keeps_path() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "?a=b"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/old/path");
        assert_eq!(request.uri.query(), Some("a=b"));
    }

    #[tokio::test]
    async fn rewrite_expands_strip_path_prefix_and_method() {
        let mut request = request();
        request
            .vars
            .insert("prefix".to_string(), "/old".to_string());
        let handler = RewriteHandler::from_json(
            &serde_json::json!({
                "handler": "rewrite",
                "method": "{http.request.method}",
                "strip_path_prefix": "{http.vars.prefix}"
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_unknown_placeholder_expands_to_empty() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "/x/{not.a.placeholder}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/x/");
    }

    #[tokio::test]
    async fn rewrite_with_empty_uri_template_is_a_noop() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "{http.vars.missing}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/old/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn vars_handler_sets_request_variables() {
        let handler = VarsHandler::from_json(
            &serde_json::json!({"handler": "vars", "root": "/srv"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.vars.get("root").map(String::as_str), Some("/srv"));
    }

    async fn static_response(body: serde_json::Value) -> Response {
        let handler = StaticResponseHandler::from_json(&body, "handler").unwrap();
        let Outcome::Respond(response) = handler.handle(request()).await.unwrap() else {
            panic!("expected response");
        };
        response
    }

    fn content_type(response: &Response) -> Option<&str> {
        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
    }

    #[tokio::test]
    async fn static_response_string_body_gets_caddy_text_content_type() {
        // Real Caddy's staticresp.go: every non-empty non-JSON string body is
        // `text/plain; charset=utf-8`.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello oracle"
        }))
        .await;
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
        assert_eq!(response.body, Bytes::from_static(b"hello oracle"));
    }

    #[tokio::test]
    async fn static_response_json_body_gets_json_content_type() {
        for body in ["{\"a\":1}", "[1,2,3]", "  {\"nested\":true}\n"] {
            let response = static_response(serde_json::json!({
                "handler": "static_response",
                "body": body
            }))
            .await;
            assert_eq!(
                content_type(&response),
                Some("application/json"),
                "body {body:?}"
            );
        }
        // Caddy requires more than two trimmed bytes regardless of validity: `{}` is text.
        for body in ["{}", "[]", "{not json}", "[trailing", "  ", "   \n\t"] {
            let response = static_response(serde_json::json!({
                "handler": "static_response",
                "body": body
            }))
            .await;
            assert_eq!(
                content_type(&response),
                Some("text/plain; charset=utf-8"),
                "body {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn static_response_explicit_content_type_wins() {
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello",
            "headers": {"Content-Type": ["application/x-custom"]}
        }))
        .await;
        assert_eq!(content_type(&response), Some("application/x-custom"));

        // Caddy treats an empty configured value as "not set" (Header.Get == "") and replaces it
        // with the implicit type.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello",
            "headers": {"Content-Type": [""]}
        }))
        .await;
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn static_response_empty_body_has_no_content_type() {
        // Caddy only sets the implicit Content-Type when the expanded body is non-empty, and it
        // explicitly clears Content-Type afterwards so Go cannot sniff one.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": ""
        }))
        .await;
        assert_eq!(content_type(&response), None);
        assert!(response.body.is_empty());

        // A placeholder that expands to an empty string behaves like an empty body.
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.uri.query}"
            }),
            "handler",
        )
        .unwrap();
        let no_query = Request::new(Method::GET, "/no-query".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(no_query).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), None);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn static_response_content_type_uses_expanded_body_and_ignores_method() {
        // The implicit type is computed from the expanded body (Caddy computes it before writing
        // the body and independently of HEAD/GET).
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.method}"
            }),
            "handler",
        )
        .unwrap();
        let request = Request::new(Method::GET, "/".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));

        let head = Request::new(Method::HEAD, "/".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(head).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn vars_handler_expands_keys_and_values() {
        let handler = VarsHandler::from_json(
            &serde_json::json!({
                "handler": "vars",
                "prefix-{http.request.method}": "/srv/{http.request.uri.path}"
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(
            request.vars.get("prefix-GET").map(String::as_str),
            Some("/srv//old/path")
        );
    }

    // ---- request_body ---------------------------------------------------------------

    use crate::body::{BodyError, RequestBody, StreamingBody, StreamingResponse};
    use crate::router::RouterBuilder;
    use tokio::sync::mpsc;

    fn request_body_handler(json: serde_json::Value) -> RequestBodyHandler {
        RequestBodyHandler::from_json(&json, "handle[0]").expect("request_body config builds")
    }

    fn post_request_with_body(path: &str, body: &'static [u8]) -> Request {
        let mut request = test_request(Method::POST, path);
        request.body = Bytes::from_static(body);
        request
    }

    #[tokio::test]
    async fn request_body_max_size_marks_buffered_body_for_router_enforcement() {
        let handler = request_body_handler(serde_json::json!({
            "handler": "request_body",
            "max_size": 4
        }));
        // A buffered body is already read; the handler records the limit and the router turns it
        // into a 413 only when a body-consuming handler is about to run (Caddy is lazy).
        let Outcome::Continue(request) = handler
            .handle(post_request_with_body("/upload", b"12345"))
            .await
            .unwrap()
        else {
            panic!("request_body always continues");
        };
        assert_eq!(request.body, Bytes::from_static(b"12345"));
        assert_eq!(request.body_limit(), Some(4));

        let Outcome::Continue(request) = handler
            .handle(post_request_with_body("/upload", b"1234"))
            .await
            .unwrap()
        else {
            panic!("body at the limit continues");
        };
        assert_eq!(request.body, Bytes::from_static(b"1234"));
        assert_eq!(request.body_limit(), Some(4));
    }

    #[tokio::test]
    async fn request_body_limits_a_streaming_body_lazily() {
        let handler = request_body_handler(serde_json::json!({
            "handler": "request_body",
            "max_size": 4
        }));
        let (sender, receiver) = mpsc::channel::<std::result::Result<Bytes, BodyError>>(4);
        sender.send(Ok(Bytes::from_static(b"12"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"345"))).await.unwrap();
        drop(sender);
        let request = test_request(Method::POST, "/upload")
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        let Outcome::Continue(mut request) = handler.handle(request).await.unwrap() else {
            panic!("streaming bodies are limited lazily");
        };
        let error = request
            .take_body()
            .collect(None)
            .await
            .expect_err("reading past max_size must fail");
        assert!(
            matches!(error, BodyError::TooLarge { limit: 4 }),
            "{error:?}"
        );

        // A streaming body within the limit is delivered unchanged.
        let (sender, receiver) = mpsc::channel::<std::result::Result<Bytes, BodyError>>(4);
        sender.send(Ok(Bytes::from_static(b"12"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"34"))).await.unwrap();
        drop(sender);
        let request = test_request(Method::POST, "/upload")
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        let Outcome::Continue(mut request) = handler.handle(request).await.unwrap() else {
            panic!("streaming body continues");
        };
        assert_eq!(
            request.take_body().collect(None).await.unwrap(),
            Bytes::from_static(b"1234")
        );
    }

    #[tokio::test]
    async fn request_body_set_replaces_body_and_content_length() {
        let handler = request_body_handler(serde_json::json!({
            "handler": "request_body",
            "set": "{http.request.method}:{not.a.placeholder}"
        }));
        let mut request = post_request_with_body("/upload", b"old body");
        request
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("8"));
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("set continues to the next handler");
        };
        assert_eq!(
            request.body,
            Bytes::from_static(b"POST:{not.a.placeholder}")
        );
        assert_eq!(
            request.headers[http::header::CONTENT_LENGTH],
            request.body.len().to_string().as_str()
        );
        assert!(!request.has_streaming_body());
    }

    #[tokio::test]
    async fn request_body_set_then_max_size_marks_the_replacement() {
        let handler = request_body_handler(serde_json::json!({
            "handler": "request_body",
            "set": "12345",
            "max_size": 4
        }));
        let request = test_request(Method::POST, "/upload");
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("request_body continues; the router enforces the limit");
        };
        assert_eq!(request.body, Bytes::from_static(b"12345"));
        assert_eq!(request.body_limit(), Some(4));
    }

    #[tokio::test]
    async fn request_body_zero_max_size_means_unlimited() {
        let handler = request_body_handler(serde_json::json!({
            "handler": "request_body",
            "max_size": 0
        }));
        let large = Bytes::from(vec![b'x'; 1024]);
        let mut request = test_request(Method::POST, "/upload");
        request.body = large.clone();
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("max_size 0 is unlimited");
        };
        assert_eq!(request.body, large);
    }

    #[test]
    fn request_body_config_rejects_invalid_and_unknown_fields() {
        for (field, value, expected_path) in [
            ("max_size", serde_json::json!("4"), "handle[0].max_size"),
            ("max_size", serde_json::json!(-1), "handle[0].max_size"),
            ("max_size", serde_json::json!(1.5), "handle[0].max_size"),
            (
                "max_size",
                serde_json::json!((i64::MAX as u64) + 1),
                "handle[0].max_size",
            ),
            ("set", serde_json::json!(5), "handle[0].set"),
        ] {
            let error = RequestBodyHandler::from_json(
                &serde_json::json!({"handler": "request_body", field: value}),
                "handle[0]",
            )
            .expect_err("invalid request_body field must fail");
            assert!(error.to_string().contains(expected_path), "{field} {error}");
        }
        let error = RequestBodyHandler::from_json(
            &serde_json::json!({"handler": "request_body", "curves": ["x25519"]}),
            "handle[0]",
        )
        .expect_err("unknown request_body field must fail");
        assert!(error.to_string().contains("handle[0].curves"), "{error}");
        assert!(error.to_string().contains("unsupported request_body field"));

        // The object itself must be a JSON object.
        let error = RequestBodyHandler::from_json(&serde_json::json!("request_body"), "handle[0]")
            .expect_err("non-object fails");
        assert!(error.to_string().contains("must be an object"), "{error}");
    }

    #[tokio::test]
    async fn request_body_runs_before_later_handlers() {
        let router = RouterBuilder::new()
            .build(&[serde_json::json!({
                "handle": [
                    {"handler": "request_body", "max_size": 4},
                    {"handler": "rewrite", "uri": "/rewritten"},
                    {"handler": "static_response", "body": "{http.request.uri}"}
                ]
            })])
            .expect("router builds");
        // `request_body` itself does not force buffering.
        assert!(!router.requires_buffered_request_body());

        // The later handlers here never read the body, so Caddy's lazy limit does not fire: the
        // oversized body passes through to `static_response` (oracle: 200 "static ok").
        let response = router
            .handle(post_request_with_body("/upload", b"12345"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"/rewritten"));

        let response = router
            .handle(post_request_with_body("/upload", b"1234"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"/rewritten"));
    }

    /// Stub for the `reverse_proxy` module id: records the buffered request body it received.
    struct ProxyBodyStub;

    #[async_trait]
    impl Handler for ProxyBodyStub {
        fn name(&self) -> &'static str {
            "reverse_proxy"
        }

        fn requires_buffered_request_body(&self) -> bool {
            true
        }

        async fn handle(&self, request: Request) -> Result<Outcome> {
            Ok(Outcome::Respond(Response {
                status: StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: request.body,
            }))
        }
    }

    #[tokio::test]
    async fn request_body_orders_before_a_body_consuming_proxy() {
        let factory: crate::router::CustomHandlerFactory = Arc::new(|value, _path| {
            Ok(
                match value.get("handler").and_then(serde_json::Value::as_str) {
                    Some("reverse_proxy") => Some(Arc::new(ProxyBodyStub) as crate::SharedHandler),
                    _ => None,
                },
            )
        });
        let router = RouterBuilder::new()
            .with_custom_handler(factory)
            .build(&[serde_json::json!({
                "handle": [
                    {"handler": "request_body", "max_size": 4},
                    {"handler": "headers", "response": {"set": {"X-Limit": ["yes"]}}},
                    {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:1"}]}
                ]
            })])
            .expect("router builds");
        // `reverse_proxy` forces the router to buffer request bodies, so the limit is enforced
        // eagerly by `request_body` before the proxy sees the body.
        assert!(router.requires_buffered_request_body());

        let response = router
            .handle(post_request_with_body("/upload", b"12345"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        // Caddy's default request-body-limit error has an empty body and no content type
        // (oracle v2.11.7), while response headers staged by preceding handlers still apply.
        assert!(response.body.is_empty());
        assert_eq!(response.headers["x-limit"], "yes");

        let response = router
            .handle(post_request_with_body("/upload", b"1234"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"1234"));
    }

    /// Streaming `reverse_proxy` stub: reports the buffering capability as false (like the real
    /// proxy without retries) and consumes the request body frame by frame.
    struct StreamingProxyStub {
        consumed: Arc<std::sync::Mutex<Vec<Bytes>>>,
    }

    #[async_trait]
    impl Handler for StreamingProxyStub {
        fn name(&self) -> &'static str {
            "reverse_proxy"
        }

        async fn handle(&self, _request: Request) -> Result<Outcome> {
            panic!("streaming proxy stub uses the streaming path");
        }

        async fn handle_streaming(&self, mut request: Request) -> Result<StreamingOutcome> {
            let mut body = request.take_body();
            let mut consumed = Vec::new();
            while let Some(frame) = body.next_frame().await {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    consumed.push(data);
                }
            }
            *self.consumed.lock().expect("lock") = consumed;
            Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                Response::text(StatusCode::OK, "proxied"),
            )))
        }
    }

    fn streaming_proxy_factory(
        consumed: Arc<std::sync::Mutex<Vec<Bytes>>>,
    ) -> crate::router::CustomHandlerFactory {
        Arc::new(move |value, _path| {
            Ok(
                match value.get("handler").and_then(serde_json::Value::as_str) {
                    Some("reverse_proxy") => Some(Arc::new(StreamingProxyStub {
                        consumed: Arc::clone(&consumed),
                    }) as crate::SharedHandler),
                    _ => None,
                },
            )
        })
    }

    fn streaming_request(chunks: Vec<&'static [u8]>) -> Request {
        let (sender, receiver) = mpsc::channel::<std::result::Result<Bytes, BodyError>>(8);
        for chunk in chunks {
            sender.try_send(Ok(Bytes::from_static(chunk))).unwrap();
        }
        drop(sender);
        test_request(Method::POST, "/upload")
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)))
    }

    #[tokio::test]
    async fn streaming_proxy_receives_chunks_without_forced_buffering() {
        let consumed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let router = RouterBuilder::new()
            .with_custom_handler(streaming_proxy_factory(Arc::clone(&consumed)))
            .build(&[serde_json::json!({
                "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:9"}]}]
            })])
            .expect("router builds");
        // Capability composition: the streaming proxy does not ask the server to buffer, but it is
        // marked as a body consumer for `request_body` limit enforcement.
        assert!(!router.requires_buffered_request_body());
        assert!(router.consumes_request_body());

        let response = router
            .handle_streaming(streaming_request(vec![b"abc", b"defg", b"hi"]))
            .await
            .unwrap();
        let response = response.into_buffered().await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            *consumed.lock().expect("lock"),
            vec![
                Bytes::from_static(b"abc"),
                Bytes::from_static(b"defg"),
                Bytes::from_static(b"hi")
            ],
            "the proxy stub must receive the streamed frames without the server buffering them"
        );
    }

    #[tokio::test]
    async fn request_body_enforces_limit_for_a_streaming_body_consumer() {
        let consumed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let router = RouterBuilder::new()
            .with_custom_handler(streaming_proxy_factory(Arc::clone(&consumed)))
            .build(&[serde_json::json!({
                "handle": [
                    {"handler": "request_body", "max_size": 4},
                    {"handler": "reverse_proxy", "upstreams": [{"dial": "127.0.0.1:9"}]}
                ]
            })])
            .expect("router builds");
        assert!(!router.requires_buffered_request_body());
        assert!(router.consumes_request_body());

        // Over the limit: the router reads the stream up to the limit and returns Caddy's 413
        // before the streaming consumer sees a proxy-side read error.
        let response = router
            .handle_streaming(streaming_request(vec![b"12", b"345"]))
            .await
            .unwrap();
        let response = response.into_buffered().await.unwrap();
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(response.body.is_empty());
        assert!(
            consumed.lock().expect("lock").is_empty(),
            "the streaming consumer must not run for an over-limit body"
        );

        // Within the limit: the consumer receives the complete body. The router buffers only when
        // a `request_body` limit is configured and the next handler consumes the body, so the
        // lazy `413` outcome matches Caddy.
        let response = router
            .handle_streaming(streaming_request(vec![b"12", b"34"]))
            .await
            .unwrap();
        let response = response.into_buffered().await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            consumed.lock().expect("lock").concat(),
            Bytes::from_static(b"1234")
        );
    }

    // ---- map handler --------------------------------------------------------------------

    fn map_handler(json: serde_json::Value) -> MapHandler {
        MapHandler::from_json(&json, "handle[0]").expect("map handler builds")
    }

    fn map_request(path: &str) -> Request {
        test_request(Method::GET, path)
    }

    async fn run_map(handler: &MapHandler, path: &str) -> Request {
        let Outcome::Continue(request) = handler.handle(map_request(path)).await.unwrap() else {
            panic!("map continues to the next handler");
        };
        request
    }

    #[tokio::test]
    async fn map_exact_mapping_and_defaults_set_placeholders() {
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{mapped}"],
            "mappings": [{"input": "/foo", "outputs": ["FOO"]}],
            "defaults": ["DEFAULT"]
        }));
        let request = run_map(&handler, "/foo").await;
        assert_eq!(request.vars.get("mapped").map(String::as_str), Some("FOO"));
        assert_eq!(
            request.replace_known("{mapped}"),
            "FOO",
            "mapped placeholders resolve through the replacer"
        );
        let request = run_map(&handler, "/other").await;
        assert_eq!(
            request.vars.get("mapped").map(String::as_str),
            Some("DEFAULT")
        );
    }

    #[tokio::test]
    async fn map_multiple_destinations_positional_outputs_and_null_fallthrough() {
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{one}", "{two}"],
            "mappings": [
                // The null output for `{one}` is skipped, so the regexp mapping below can still
                // match the same input (literal and regexp mappings may overlap).
                {"input": "/foo", "outputs": [null, "exact-two"]},
                {"input_regexp": "foo", "outputs": ["regexp-one", null]}
            ],
            "defaults": ["default-one", "default-two"]
        }));
        let request = run_map(&handler, "/foo").await;
        assert_eq!(
            request.vars.get("one").map(String::as_str),
            Some("regexp-one")
        );
        // The regexp mapping's null output for `{two}` is skipped, so the exact mapping won.
        assert_eq!(
            request.vars.get("two").map(String::as_str),
            Some("exact-two")
        );
    }

    #[tokio::test]
    async fn map_regexp_captures_and_expansion() {
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{api}", "{fragment}", "{case}"],
            "mappings": [
                {"input_regexp": "^/api/(.*)$", "outputs": ["api:${1}", null, null]},
                {"input_regexp": "(xyz)", "outputs": [null, "...${1}...", null]},
                {"input_regexp": "(?i)HELLO", "outputs": [null, null, "hello"]}
            ]
        }));
        let request = run_map(&handler, "/api/users").await;
        assert_eq!(
            request.vars.get("api").map(String::as_str),
            Some("api:users")
        );
        let request = run_map(&handler, "/ABCxyzDEF").await;
        assert_eq!(
            request.vars.get("fragment").map(String::as_str),
            Some("...xyz...")
        );
        let request = run_map(&handler, "/sayhello").await;
        assert_eq!(request.vars.get("case").map(String::as_str), Some("hello"));
        // `$1` without braces is also a Go-style capture reference.
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{out}"],
            "mappings": [{"input_regexp": "^/([a-z]+)$", "outputs": ["x-$1"]}]
        }));
        let request = run_map(&handler, "/word").await;
        assert_eq!(request.vars.get("out").map(String::as_str), Some("x-word"));
    }

    #[tokio::test]
    async fn map_scalar_output_types_and_placeholder_expansion() {
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{int}", "{float}", "{bool}", "{quoted}", "{combined}"],
            "mappings": [{
                "input": "/types",
                "outputs": [42, 1.5, true, "42", "{http.request.method}-mapped"]
            }]
        }));
        let request = run_map(&handler, "/types").await;
        assert_eq!(request.vars.get("int").map(String::as_str), Some("42"));
        assert_eq!(request.vars.get("float").map(String::as_str), Some("1.5"));
        assert_eq!(request.vars.get("bool").map(String::as_str), Some("true"));
        assert_eq!(request.vars.get("quoted").map(String::as_str), Some("42"));
        assert_eq!(
            request.vars.get("combined").map(String::as_str),
            Some("GET-mapped"),
            "exact mappings expand placeholders in their outputs"
        );
    }

    #[tokio::test]
    async fn map_no_mapping_and_absent_defaults_leave_placeholders_empty() {
        let handler = map_handler(serde_json::json!({
            "handler": "map",
            "source": "{http.request.uri.path}",
            "destinations": ["{out}"],
            "mappings": [{"input": "/foo", "outputs": ["FOO"]}]
        }));
        let request = run_map(&handler, "/missing").await;
        assert_eq!(request.vars.get("out").map(String::as_str), Some(""));
        assert_eq!(request.replace_known("{out}"), "");
    }

    #[tokio::test]
    async fn map_chains_with_headers_and_static_response() {
        let routes = vec![serde_json::json!({
            "handle": [
                {"handler": "map",
                 "source": "{http.request.uri.path}",
                 "destinations": ["{greeting}"],
                 "mappings": [{"input": "/hello", "outputs": ["hi"]}],
                 "defaults": ["default"]},
                {"handler": "headers", "response": {"set": {"X-Greeting": ["{greeting}"]}}},
                {"handler": "static_response", "body": "{greeting} {http.request.uri.path}"}
            ]
        })];
        let router = RouterBuilder::new().build(&routes).expect("router builds");

        let response = router.handle(map_request("/hello")).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"hi /hello"));
        assert_eq!(response.headers["x-greeting"], "hi");

        let response = router.handle(map_request("/other")).await.unwrap();
        assert_eq!(response.body, Bytes::from_static(b"default /other"));
        assert_eq!(response.headers["x-greeting"], "default");
    }

    #[test]
    fn map_config_is_strict() {
        let invalid = [
            // Destination is not exactly one placeholder.
            serde_json::json!({"handler":"map","destinations":["foo"]}),
            serde_json::json!({"handler":"map","destinations":["{}"]}),
            serde_json::json!({"handler":"map","destinations":["{a}{b}"]}),
            // Outputs/defaults must match the destination count.
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input":"x","outputs":["1","2"]}]}),
            serde_json::json!({"handler":"map","destinations":["{a}"],"defaults":["1","2"]}),
            // Ambiguous / duplicate mappings.
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input":"x","input_regexp":"x","outputs":["1"]}]}),
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input":"x","outputs":["1"]},{"input":"x","outputs":["2"]}]}),
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input_regexp":"x","outputs":["1"]},
                            {"input_regexp":"x","outputs":["2"]}]}),
            // Invalid or unsupported regular expressions.
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input_regexp":"(","outputs":["1"]}]}),
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input_regexp":"\\bword","outputs":["1"]}]}),
            // Non-scalar outputs and unknown fields are rejected loudly.
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input":"x","outputs":[["nested"]]}]}),
            serde_json::json!({"handler":"map","unknown":true}),
            serde_json::json!({"handler":"map","destinations":["{a}"],
                "mappings":[{"input":"x","outputs":["1"],"extra":true}]}),
            serde_json::json!({"handler":"map","source":42}),
        ];
        for json in invalid {
            let error = MapHandler::from_json(&json, "handle[0]")
                .expect_err("invalid map config must fail");
            let message = error.to_string();
            assert!(
                message.contains("handle[0]"),
                "error must name the config path: {message} for {json}"
            );
        }
    }

    // ---- rewrite handler fields --------------------------------------------------------

    fn rewrite_handler(json: serde_json::Value) -> RewriteHandler {
        RewriteHandler::from_json(&json, "handle[0]").expect("rewrite handler builds")
    }

    async fn run_rewrite(handler: &RewriteHandler, uri: &str) -> Request {
        let Outcome::Continue(request) = handler
            .handle(test_request(Method::GET, uri))
            .await
            .unwrap()
        else {
            panic!("rewrite continues to the next handler");
        };
        request
    }

    #[tokio::test]
    async fn rewrite_strip_path_suffix_preserves_query() {
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "strip_path_suffix": ".html"
        }));
        let request = run_rewrite(&handler, "/page.html?user=bob").await;
        assert_eq!(request.uri.path(), "/page");
        assert_eq!(request.uri.query(), Some("user=bob"));
        // Suffix matching is case-insensitive like Caddy's trimPathSuffix.
        let request = run_rewrite(&handler, "/PAGE.HTML").await;
        assert_eq!(request.uri.path(), "/PAGE");
        // A non-matching suffix is a no-op.
        let request = run_rewrite(&handler, "/page.htm").await;
        assert_eq!(request.uri.path(), "/page.htm");
    }

    #[tokio::test]
    async fn rewrite_uri_substring_replaces_path_and_query_with_limit() {
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "uri_substring": [
                {"find": "/old", "replace": "/new"},
                {"find": "a", "replace": "b", "limit": 1}
            ]
        }));
        let request = run_rewrite(&handler, "/old/a/a?q=a&x=aa").await;
        assert_eq!(request.uri.path(), "/new/b/a");
        // Caddy applies the per-string limit separately to the path and the query.
        assert_eq!(request.uri.query(), Some("q=b&x=aa"));
    }

    #[tokio::test]
    async fn rewrite_path_regexp_expands_captures() {
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "path_regexp": [
                {"find": "^/old/(.*)$", "replace": "/new/$1"}
            ]
        }));
        let request = run_rewrite(&handler, "/old/rest?x=1").await;
        assert_eq!(request.uri.path(), "/new/rest");
        assert_eq!(request.uri.query(), Some("x=1"));

        // Placeholders in the replacement are expanded before regex capture expansion.
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "path_regexp": [
                {"find": "^/(.*)$", "replace": "/{http.request.method}/$1"}
            ]
        }));
        let request = run_rewrite(&handler, "/thing").await;
        assert_eq!(request.uri.path(), "/GET/thing");
    }

    #[tokio::test]
    async fn rewrite_query_operations_follow_caddy_order_and_encoding() {
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "query": {
                "rename": [{"key": "changethis", "val": "changed"}],
                "set": [
                    {"key": "taz", "val": "test"},
                    {"key": "key=value", "val": "example"}
                ],
                "add": [
                    {"key": "foo", "val": "bar"},
                    {"key": "foo1", "val": "baz"}
                ],
                "replace": [{"key": "findme", "search": "value", "replace": "replacement"}],
                "delete": ["baz"]
            }
        }));
        let request = run_rewrite(&handler, "/path?changethis=1&baz=2&findme=value&foo=old").await;
        assert_eq!(
            request.uri.query(),
            Some("changed=1&findme=replacement&foo=old&foo=bar&foo1=baz&key%3Dvalue=example&taz=test")
        );
    }

    #[tokio::test]
    async fn rewrite_query_replace_supports_star_and_regexp() {
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "query": {
                "replace": [{
                    "key": "*",
                    "search_regexp": "v([0-9])",
                    "replace": "x${1}"
                }]
            }
        }));
        let request = run_rewrite(&handler, "/x?a=v1&b=v2").await;
        assert_eq!(request.uri.query(), Some("a=x1&b=x2"));
    }

    #[tokio::test]
    async fn rewrite_uri_substring_applies_to_braces() {
        // Caddy fixture `uri_replace_brace_escape`: escaped braces in the configured find/replace
        // are literal backslash sequences; here a percent-encoded brace in the query is replaced.
        let handler = rewrite_handler(serde_json::json!({
            "handler": "rewrite",
            "uri_substring": [
                {"find": "%5C%7D", "replace": "%7D"},
                {"find": "%5C%7B", "replace": "%7B"}
            ]
        }));
        let request = run_rewrite(&handler, "/x?q=%5C%7D%5C%7B").await;
        assert_eq!(request.uri.query(), Some("q=%7D%7B"));
    }

    #[test]
    fn rewrite_config_is_strict() {
        let invalid = [
            serde_json::json!({"handler": "rewrite", "unknown": true}),
            serde_json::json!({"handler": "rewrite", "uri": 42}),
            serde_json::json!({"handler": "rewrite", "strip_path_suffix": 42}),
            serde_json::json!({"handler": "rewrite", "uri_substring": "x"}),
            serde_json::json!({"handler": "rewrite",
                "uri_substring": [{"find": "x", "replace": "y", "limit": "1"}]}),
            serde_json::json!({"handler": "rewrite",
                "uri_substring": [{"find": "x", "unknown": true}]}),
            serde_json::json!({"handler": "rewrite", "path_regexp": "x"}),
            serde_json::json!({"handler": "rewrite",
                "path_regexp": [{"find": "", "replace": "x"}]}),
            serde_json::json!({"handler": "rewrite",
                "path_regexp": [{"find": "(", "replace": "x"}]}),
            serde_json::json!({"handler": "rewrite", "query": "x"}),
            serde_json::json!({"handler": "rewrite", "query": {"unknown": []}}),
            serde_json::json!({"handler": "rewrite", "query": {"delete": [42]}}),
            serde_json::json!({"handler": "rewrite", "query": {"set": [{"key": "a", "unknown": "b"}]}}),
            serde_json::json!({"handler": "rewrite", "query": {"replace": [{
                "key": "a", "search_regexp": "(", "replace": "b"}]}}),
        ];
        for json in invalid {
            let error = RewriteHandler::from_json(&json, "handle[0]")
                .expect_err("invalid rewrite config must fail");
            assert!(
                error.to_string().contains("handle[0]"),
                "error must name the config path: {error} for {json}"
            );
        }
    }

    #[tokio::test]
    async fn adapted_uri_query_operations_fixture_builds_and_runs() {
        use crate::router::RouterBuilder;

        // Canonical JSON from upstream `uri_query_operations.caddyfiletest` (Caddy v2.11.7).
        let routes = vec![serde_json::json!({
            "handle": [
                {"handler": "rewrite", "query": {"add": [{"key": "foo", "val": "bar"}]}},
                {"handler": "rewrite", "query": {"delete": ["baz"]}},
                {"handler": "rewrite", "query": {"set": [{"key": "taz", "val": "test"}]}},
                {"handler": "rewrite", "query": {"set": [{"key": "key=value", "val": "example"}]}},
                {"handler": "rewrite", "query": {"rename": [{"key": "changethis", "val": "changed"}]}},
                {"handler": "rewrite", "query": {
                    "add": [{"key": "foo1", "val": "baz"}],
                    "replace": [{"key": "findme", "replace": "replacement",
                                 "search_regexp": "value"}]
                }},
                {"handler": "static_response", "body": "{http.request.uri.query}"}
            ]
        })];
        let router = RouterBuilder::new()
            .build(&routes)
            .expect("fixture routes build");
        let request = test_request(Method::GET, "/path?changethis=1&baz=2&findme=value&foo=old");
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body,
            Bytes::from_static(
                b"changed=1&findme=replacement&foo=old&foo=bar&foo1=baz&key%3Dvalue=example&taz=test"
            )
        );
    }

    #[tokio::test]
    async fn adapted_uri_replace_brace_escape_fixture_builds_and_runs() {
        use crate::router::RouterBuilder;

        // Canonical JSON from upstream `uri_replace_brace_escape.caddyfiletest`.
        let routes = vec![serde_json::json!({
            "handle": [
                {"handler": "rewrite",
                 "uri_substring": [{"find": "\\}", "replace": "%7D"}]},
                {"handler": "rewrite",
                 "uri_substring": [{"find": "\\{", "replace": "%7B"}]},
                {"handler": "static_response", "body": "{http.request.uri.query}"}
            ]
        })];
        let router = RouterBuilder::new()
            .build(&routes)
            .expect("fixture routes build");
        let request = test_request(Method::GET, "/path?q=test");
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"q=test"));
    }
}
