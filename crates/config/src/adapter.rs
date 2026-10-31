//! Caddyfile → Caddy JSON adapter.
//!
//! The adapter mirrors Caddy's `httpcaddyfile` output for a documented subset of directives and
//! matchers. Compatibility strategy:
//!
//! * Where a construct is supported, the emitted JSON is intended to be *semantically identical*
//!   to Caddy v2.11.7's `caddy adapt` output (curated upstream golden tests assert exact equality).
//! * Where a construct is recognised but not implemented, adaptation fails with a located error
//!   naming the construct. Silent fallback would be a compatibility lie.
//!
//! Supported directives and matchers are listed in `docs/compatibility/CADDYFILE.md` in the
//! program repository.

use std::collections::BTreeMap;
use std::net::IpAddr;

use caddy_rs_core::{AdaptedConfig, ConfigAdapter, Error as CoreError};
use serde_json::{json, Map, Value};

use crate::lexer::Position;
use crate::parser::{self, AutoHttpsMode, Directive, SiteAddress, SiteBlock};

/// Canonical directive order, mirroring Caddy's default order for the supported subset.
const DIRECTIVE_ORDER: &[&str] = &[
    "root",
    "header",
    "redir",
    "respond",
    "route",
    "encode",
    "handle",
    "handle_path",
    "method",
    "reverse_proxy",
    "file_server",
];

/// The Caddyfile adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaddyfileAdapter;

impl ConfigAdapter for CaddyfileAdapter {
    fn name(&self) -> &'static str {
        "caddyfile"
    }

    fn adapt(&self, input: &[u8]) -> caddy_rs_core::Result<AdaptedConfig> {
        let text = std::str::from_utf8(input).map_err(|source| {
            CoreError::invalid("Caddyfile", format!("input is not valid UTF-8: {source}"))
        })?;
        adapt(text)
    }
}

/// Adapt a Caddyfile string to Caddy JSON.
pub fn adapt(input: &str) -> caddy_rs_core::Result<AdaptedConfig> {
    let file = parser::parse(input).map_err(parse_error)?;
    let options = &file.options;
    let http_port = options.http_port.unwrap_or(80);
    let https_port = options.https_port.unwrap_or(443);
    let auto_https_off = matches!(options.auto_https, Some(AutoHttpsMode::Off));
    let mut warnings = options.warnings.clone();

    let mut seen_addresses: BTreeMap<String, Position> = BTreeMap::new();
    let mut servers: Vec<ServerBuilder> = Vec::new();

    for site in &file.sites {
        let site_routes = build_site_routes(site, &mut warnings)?;
        for address in &site.addresses {
            let normalized = format!(
                "{}://{}:{}",
                address.scheme.as_deref().unwrap_or("auto"),
                address.host,
                address.effective_port(http_port, https_port)
            );
            if let Some(previous) = seen_addresses.insert(normalized.clone(), site.position) {
                return Err(adapter_error(
                    site.position,
                    format!(
                        "ambiguous site definition for address `{}` (first defined at {previous})",
                        address.raw
                    ),
                ));
            }

            let port = address.effective_port(http_port, https_port);
            let listen = listen_address(address, port);
            let https = address.is_https(http_port, https_port);
            let index = match servers.iter().position(|server| server.listen == listen) {
                Some(index) => index,
                None => {
                    servers.push(ServerBuilder {
                        listen,
                        routes: Vec::new(),
                        https,
                    });
                    servers.len() - 1
                }
            };
            let server = &mut servers[index];
            server.https |= https;
            if address.host.is_empty() {
                server.routes.extend(site_routes.clone());
            } else {
                let host = address.host.trim_start_matches('[').trim_end_matches(']');
                server.routes.push(json!({
                    "match": [{"host": [host]}],
                    "handle": [{
                        "handler": "subroute",
                        "routes": site_routes,
                    }],
                    "terminal": true,
                }));
            }
        }
    }

    let mut server_map = Map::new();
    for (index, server) in servers.into_iter().enumerate() {
        let mut object = Map::new();
        object.insert("listen".to_string(), json!([server.listen]));
        object.insert("routes".to_string(), Value::Array(server.routes));
        if auto_https_off {
            object.insert("automatic_https".to_string(), json!({"disable": true}));
        } else if matches!(options.auto_https, Some(AutoHttpsMode::DisableRedirects)) {
            object.insert(
                "automatic_https".to_string(),
                json!({"disable_redirects": true}),
            );
        } else if matches!(options.auto_https, Some(AutoHttpsMode::IgnoreLoadedCerts)) {
            object.insert(
                "automatic_https".to_string(),
                json!({"ignore_loaded_certs": true}),
            );
        }
        if server.https && auto_https_off {
            object.insert("tls_connection_policies".to_string(), json!([{}]));
        }
        server_map.insert(format!("srv{index}"), Value::Object(object));
    }

    let config = json!({
        "apps": {
            "http": {
                "servers": Value::Object(server_map),
            }
        }
    });

    Ok(AdaptedConfig { config, warnings })
}

struct ServerBuilder {
    listen: String,
    routes: Vec<Value>,
    https: bool,
}

fn listen_address(address: &SiteAddress, port: u16) -> String {
    if address.host.parse::<IpAddr>().is_ok() {
        format!("{}:{}", address.host, port)
    } else {
        format!(":{port}")
    }
}

fn build_site_routes(
    site: &SiteBlock,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Vec<Value>> {
    let matchers = collect_matchers(&site.directives)?;
    build_routes(&site.directives, &matchers, true, warnings)
}

fn collect_matchers(directives: &[Directive]) -> caddy_rs_core::Result<BTreeMap<String, Value>> {
    let mut matchers = BTreeMap::new();
    for directive in directives {
        let Some(name) = directive.name.strip_prefix('@') else {
            continue;
        };
        if name.is_empty() {
            return Err(adapter_error(
                directive.position,
                "matcher name after `@` must not be empty",
            ));
        }
        let object = if directive.block.is_empty() {
            matcher_from_inline_args(&directive.args, directive.position)?
        } else {
            matcher_from_directives(&directive.block)?
        };
        matchers.insert(name.to_string(), object);
    }
    Ok(matchers)
}

fn matcher_from_inline_args(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let Some(name) = args.first() else {
        return Err(adapter_error(
            position,
            "named matcher needs a matcher on the same line or a block",
        ));
    };
    matcher_from_directive(name, &args[1..], position)
}

fn matcher_from_directives(directives: &[Directive]) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    for directive in directives {
        if directive.name == "not" {
            if directive.block.is_empty() {
                return Err(adapter_error(
                    directive.position,
                    "matcher `not` must be used with a block",
                ));
            }
            let inner = matcher_from_directives(&directive.block)?;
            merge_matcher(&mut object, json!({"not": [inner]}), directive.position)?;
            continue;
        }
        let value = matcher_from_directive(&directive.name, &directive.args, directive.position)?;
        merge_matcher(&mut object, value, directive.position)?;
    }
    Ok(Value::Object(object))
}

fn matcher_from_directive(
    name: &str,
    args: &[String],
    position: Position,
) -> caddy_rs_core::Result<Value> {
    match name {
        "host" | "path" | "method" => {
            if args.is_empty() {
                return Err(adapter_error(
                    position,
                    format!("matcher `{name}` requires at least one argument"),
                ));
            }
            Ok(json!({ name: args }))
        }
        "header" => {
            let Some(field) = args.first() else {
                return Err(adapter_error(
                    position,
                    "matcher `header` requires a field name",
                ));
            };
            let value = args.get(1).cloned().unwrap_or_else(|| "*".to_string());
            Ok(json!({"header": {field: [value]}}))
        }
        "path_regexp" => {
            let (regexp_name, pattern) = match args {
                [pattern] => (None, pattern),
                [name, pattern, ..] => (Some(name.clone()), pattern),
                _ => {
                    return Err(adapter_error(
                        position,
                        "matcher `path_regexp` requires [name] and a pattern",
                    ))
                }
            };
            let mut object = Map::new();
            if let Some(name) = regexp_name {
                object.insert("name".to_string(), Value::String(name));
            }
            object.insert("pattern".to_string(), Value::String(pattern.clone()));
            Ok(json!({"path_regexp": Value::Object(object)}))
        }
        "query" => {
            if args.len() < 2 {
                return Err(adapter_error(
                    position,
                    "matcher `query` requires a key and value",
                ));
            }
            Ok(json!({"query": {args[0].clone(): [args[1].clone()]}}))
        }
        "not" => {
            // A `not` block is represented by the parser as a nested directive list, which the
            // caller handles via `matcher_from_directives`; inline `not` has no arguments.
            Err(adapter_error(
                position,
                "matcher `not` must be used with a block",
            ))
        }
        other => Err(adapter_error(
            position,
            format!("matcher `{other}` is not supported by this build"),
        )),
    }
}

fn merge_matcher(
    object: &mut Map<String, Value>,
    value: Value,
    position: Position,
) -> caddy_rs_core::Result<()> {
    let Value::Object(value) = value else {
        return Err(adapter_error(
            position,
            "internal: matcher is not an object",
        ));
    };
    for (key, incoming) in value {
        match object.get_mut(&key) {
            None => {
                object.insert(key, incoming);
            }
            Some(Value::Array(existing)) => {
                if let Value::Array(mut incoming) = incoming {
                    existing.append(&mut incoming);
                }
            }
            Some(Value::Object(existing)) => {
                if let Value::Object(incoming) = incoming {
                    for (field, value) in incoming {
                        match existing.get_mut(&field) {
                            Some(Value::Array(values)) => {
                                if let Value::Array(mut value) = value {
                                    values.append(&mut value);
                                }
                            }
                            None => {
                                existing.insert(field, value);
                            }
                            Some(_) => {}
                        }
                    }
                }
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn matcher_for_args(
    args: &mut Vec<String>,
    matchers: &BTreeMap<String, Value>,
    position: Position,
) -> caddy_rs_core::Result<Option<Value>> {
    let Some(first) = args.first() else {
        return Ok(None);
    };
    if let Some(name) = first.strip_prefix('@') {
        let Some(matcher) = matchers.get(name) else {
            return Err(adapter_error(
                position,
                format!("named matcher `@{name}` is not defined in this site block"),
            ));
        };
        args.remove(0);
        return Ok(Some(matcher.clone()));
    }
    if first == "*" {
        // Explicit wildcard matcher: matches everything, so no matcher object is emitted.
        args.remove(0);
        return Ok(None);
    }
    if first.starts_with('/') {
        let path = args.remove(0);
        return Ok(Some(json!({"path": [path]})));
    }
    Ok(None)
}

fn build_routes(
    directives: &[Directive],
    matchers: &BTreeMap<String, Value>,
    sort: bool,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Vec<Value>> {
    let mut plain: Vec<&Directive> = Vec::new();
    let mut handled: Vec<&Directive> = Vec::new();
    for directive in directives {
        if directive.name.starts_with('@') {
            continue;
        }
        if !DIRECTIVE_ORDER.contains(&directive.name.as_str()) {
            return Err(adapter_error(
                directive.position,
                format!(
                    "directive `{}` is not supported by this build (see docs/compatibility/CADDYFILE.md)",
                    directive.name
                ),
            ));
        }
        if matches!(directive.name.as_str(), "handle" | "handle_path" | "route") {
            handled.push(directive);
        } else {
            plain.push(directive);
        }
    }

    if sort {
        plain.sort_by_key(|directive| {
            DIRECTIVE_ORDER
                .iter()
                .position(|name| *name == directive.name)
                .unwrap_or(usize::MAX)
        });
        handled.sort_by_key(|directive| {
            DIRECTIVE_ORDER
                .iter()
                .position(|name| *name == directive.name)
                .unwrap_or(usize::MAX)
        });
    }

    let mut routes = Vec::new();

    // `route` blocks and `handle` blocks are routes in their own right.
    let mut handle_routes = Vec::new();
    for directive in &handled {
        match directive.name.as_str() {
            "route" => {
                let inner = build_routes(&directive.block, matchers, false, warnings)?;
                routes.push(json!({
                    "handle": [{"handler": "subroute", "routes": inner}]
                }));
            }
            "handle" | "handle_path" => {
                let route = build_handle_route(directive, matchers, warnings)?;
                handle_routes.push(route);
            }
            _ => unreachable!("handled directive names are exhaustive"),
        }
    }
    if handle_routes.len() > 1 {
        for route in &mut handle_routes {
            route["group"] = json!("group1");
        }
    }
    routes.extend(handle_routes);

    let mut generic_handlers = Vec::new();
    for directive in plain {
        let mut args = directive.args.clone();
        let matcher = matcher_for_args(&mut args, matchers, directive.position)?;
        let handlers = build_handlers(directive, &args, warnings)?;
        if handlers.is_empty() {
            continue;
        }
        match matcher {
            Some(matcher) => routes.push(json!({
                "match": [matcher],
                "handle": handlers,
            })),
            None => generic_handlers.extend(handlers),
        }
    }
    if !generic_handlers.is_empty() {
        routes.insert(0, json!({"handle": generic_handlers}));
    }
    Ok(routes)
}

fn build_handle_route(
    directive: &Directive,
    matchers: &BTreeMap<String, Value>,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Value> {
    let mut args = directive.args.clone();
    let matcher;
    let mut strip_prefix: Option<String> = None;

    if directive.name == "handle_path" {
        let Some(prefix) = args.first().cloned() else {
            return Err(adapter_error(
                directive.position,
                "`handle_path` requires a path prefix argument",
            ));
        };
        args.remove(0);
        let (pattern, strip) = if let Some(base) = prefix.strip_suffix('*') {
            (prefix.clone(), base.trim_end_matches('/').to_string())
        } else {
            (
                format!("{prefix}*"),
                prefix.trim_end_matches('/').to_string(),
            )
        };
        matcher = Some(json!({"path": [pattern]}));
        strip_prefix = Some(strip);
    } else {
        matcher = matcher_for_args(&mut args, matchers, directive.position)?;
    }

    let mut inner = Vec::new();
    if let Some(prefix) = strip_prefix {
        inner.push(json!({
            "handle": [{"handler": "rewrite", "strip_path_prefix": prefix}]
        }));
    }
    inner.extend(build_routes(&directive.block, matchers, true, warnings)?);

    let mut route = Map::new();
    route.insert(
        "handle".to_string(),
        json!([{"handler": "subroute", "routes": inner}]),
    );
    if let Some(matcher) = matcher {
        route.insert("match".to_string(), json!([matcher]));
    }
    Ok(Value::Object(route))
}

fn build_handlers(
    directive: &Directive,
    args: &[String],
    _warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Vec<Value>> {
    let handlers = match directive.name.as_str() {
        "respond" => vec![respond_handler(args, directive.position)?],
        "redir" => vec![redirect_handler(args, directive.position)?],
        "file_server" => vec![file_server_handler(directive)?],
        "root" => vec![root_handler(args, directive.position)?],
        "method" => vec![method_handler(args, directive.position)?],
        "header" => header_handlers(directive)?,
        "encode" => vec![encode_handler(directive)?],
        "reverse_proxy" => vec![reverse_proxy_handler(directive, args)?],
        other => {
            return Err(adapter_error(
                directive.position,
                format!("directive `{other}` is not implemented by the adapter"),
            ))
        }
    };
    Ok(handlers)
}

fn respond_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("static_response"));
    match args {
        // `respond 403` is a status-only response in Caddy, not a body.
        [only] if is_status_code(only) => {
            let code: u16 = only.parse().expect("checked by is_status_code");
            object.insert("status_code".to_string(), json!(code));
        }
        [body, status, ..] => {
            if !body.is_empty() {
                object.insert("body".to_string(), json!(body));
            }
            let code: u16 = status.parse().map_err(|_| {
                adapter_error(
                    position,
                    format!("`respond` status `{status}` is not a number"),
                )
            })?;
            object.insert("status_code".to_string(), json!(code));
        }
        [body] => {
            if !body.is_empty() {
                object.insert("body".to_string(), json!(body));
            }
        }
        [] => {}
    }
    Ok(Value::Object(object))
}

fn is_status_code(value: &str) -> bool {
    value.len() == 3
        && value.chars().all(|ch| ch.is_ascii_digit())
        && matches!(value.parse::<u16>(), Ok(code) if (100..=999).contains(&code))
}

fn redirect_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let Some(location) = args.first() else {
        return Err(adapter_error(
            position,
            "`redir` requires a location argument",
        ));
    };
    let code: u16 = match args.get(1) {
        Some(code) => code.parse().map_err(|_| {
            adapter_error(position, format!("`redir` status `{code}` is not a number"))
        })?,
        None => 302,
    };
    Ok(json!({
        "handler": "static_response",
        "headers": {"Location": [location]},
        "status_code": code,
    }))
}

fn root_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let Some(root) = args.first() else {
        return Err(adapter_error(position, "`root` requires a path argument"));
    };
    Ok(json!({"handler": "vars", "root": root}))
}

fn method_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let Some(method) = args.first() else {
        return Err(adapter_error(
            position,
            "`method` requires a method argument",
        ));
    };
    Ok(json!({"handler": "rewrite", "method": method}))
}

fn header_handlers(directive: &Directive) -> caddy_rs_core::Result<Vec<Value>> {
    // Supported forms:
    //   header <Field> <value>       -> response.set
    //   header +<Field> <value>      -> response.add
    //   header -<Field>              -> response.delete
    //   header ?<Field> <value>      -> response.require + set
    let mut handlers = Vec::new();
    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    if directive.block.is_empty() {
        if directive.args.len() < 2 {
            return Err(adapter_error(
                directive.position,
                "`header` requires a field name and value (or a block)",
            ));
        }
        entries.push((directive.args[0].clone(), directive.args[1..].to_vec()));
    } else {
        for item in &directive.block {
            if matches!(item.name.as_str(), "defer" | "match") {
                return Err(adapter_error(
                    item.position,
                    "`header` block options `defer`/`match` are not supported by this build",
                ));
            }
            if item.args.is_empty() {
                entries.push((item.name.clone(), Vec::new()));
            } else {
                entries.push((item.name.clone(), vec![item.args.join(" ")]));
            }
        }
    }

    let mut sets = Map::new();
    let mut adds = Map::new();
    let mut deletes = Vec::new();
    for (raw_field, values) in entries {
        let field = raw_field.trim_end_matches(':').to_string();
        if let Some(name) = field.strip_prefix('+') {
            adds.insert(name.to_string(), json!(values));
        } else if let Some(name) = field.strip_prefix('-') {
            deletes.push(Value::String(name.to_string()));
        } else if let Some(name) = field.strip_prefix('?') {
            sets.insert(name.to_string(), json!(values));
        } else {
            sets.insert(field, json!(values));
        }
    }

    let mut response = Map::new();
    if !sets.is_empty() {
        response.insert("set".to_string(), Value::Object(sets));
    }
    if !adds.is_empty() {
        response.insert("add".to_string(), Value::Object(adds));
    }
    if !deletes.is_empty() {
        response.insert("delete".to_string(), Value::Array(deletes));
    }
    handlers.push(json!({"handler": "headers", "response": response}));
    Ok(handlers)
}

fn file_server_handler(directive: &Directive) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("file_server"));
    let mut hide: Vec<Value> = vec![json!("./Caddyfile")];
    let mut seen_hide = false;
    let mut index_names: Vec<Value> = Vec::new();

    let apply = |name: &str,
                 values: &[String],
                 object: &mut Map<String, Value>,
                 hide: &mut Vec<Value>,
                 seen_hide: &mut bool,
                 index_names: &mut Vec<Value>|
     -> caddy_rs_core::Result<()> {
        match name {
            "browse" => {
                object.insert("browse".to_string(), json!({}));
            }
            "pass_thru" => {
                object.insert("pass_thru".to_string(), json!(true));
            }
            "hide" => {
                if values.is_empty() {
                    return Err(adapter_error(
                        directive.position,
                        "`file_server hide` requires one or more paths",
                    ));
                }
                if !*seen_hide {
                    hide.clear();
                    *seen_hide = true;
                }
                hide.extend(values.iter().map(|value| json!(value)));
            }
            "index" => {
                if values.is_empty() {
                    return Err(adapter_error(
                        directive.position,
                        "`file_server index` requires one or more filenames",
                    ));
                }
                index_names.extend(values.iter().map(|value| json!(value)));
            }
            "root" => {
                let Some(root) = values.first() else {
                    return Err(adapter_error(
                        directive.position,
                        "`file_server root` requires a path",
                    ));
                };
                object.insert("root".to_string(), json!(root));
            }
            "status" => {
                let Some(status) = values.first() else {
                    return Err(adapter_error(
                        directive.position,
                        "`file_server status` requires a code",
                    ));
                };
                let code: u16 = status.parse().map_err(|_| {
                    adapter_error(
                        directive.position,
                        format!("`file_server status` value `{status}` is not a number"),
                    )
                })?;
                object.insert("status_code".to_string(), json!(code));
            }
            "disable_canonical_uris" => {
                object.insert("canonical_uris".to_string(), json!(false));
            }
            "precompressed" => {
                if values.is_empty() {
                    return Err(adapter_error(
                        directive.position,
                        "`file_server precompressed` requires at least one format",
                    ));
                }
                object.insert("precompressed".to_string(), json!({"order": values}));
            }
            other => {
                return Err(adapter_error(
                    directive.position,
                    format!("`file_server` option `{other}` is not supported by this build"),
                ))
            }
        }
        Ok(())
    };

    // Options written directly after the directive name.
    let args = &directive.args;
    let mut index = 0;
    while index < args.len() {
        let name = args[index].clone();
        index += 1;
        if !is_file_server_option(&name) {
            return Err(adapter_error(
                directive.position,
                format!("`file_server` option `{name}` is not supported by this build"),
            ));
        }
        let takes_values = matches!(name.as_str(), "hide" | "index" | "precompressed");
        let mut values = Vec::new();
        if takes_values {
            while index < args.len() && !is_file_server_option(&args[index]) {
                values.push(args[index].clone());
                index += 1;
            }
        } else if matches!(name.as_str(), "root" | "status") {
            if let Some(value) = args.get(index) {
                values.push(value.clone());
                index += 1;
            }
        }
        apply(
            &name,
            &values,
            &mut object,
            &mut hide,
            &mut seen_hide,
            &mut index_names,
        )?;
    }

    // Options written in a nested block.
    for item in &directive.block {
        apply(
            &item.name,
            &item.args,
            &mut object,
            &mut hide,
            &mut seen_hide,
            &mut index_names,
        )?;
    }

    if !hide.is_empty() {
        object.insert("hide".to_string(), Value::Array(hide));
    }
    if !index_names.is_empty() {
        object.insert("index_names".to_string(), Value::Array(index_names));
    }
    Ok(Value::Object(object))
}

fn is_file_server_option(value: &str) -> bool {
    matches!(
        value,
        "browse"
            | "pass_thru"
            | "hide"
            | "index"
            | "root"
            | "status"
            | "precompressed"
            | "disable_canonical_uris"
    )
}

fn encode_handler(directive: &Directive) -> caddy_rs_core::Result<Value> {
    let mut encodings = Map::new();
    let mut prefer = Vec::new();
    if directive.block.is_empty() {
        for name in &directive.args {
            if !matches!(name.as_str(), "gzip" | "zstd") {
                return Err(adapter_error(
                    directive.position,
                    format!("unsupported encoding `{name}`; expected gzip or zstd"),
                ));
            }
            encodings.insert(name.clone(), json!({}));
            prefer.push(json!(name));
        }
        if prefer.is_empty() {
            encodings.insert("zstd".to_string(), json!({}));
            encodings.insert("gzip".to_string(), json!({}));
            prefer.extend([json!("zstd"), json!("gzip")]);
        }
    } else {
        let mut minimum_length = None;
        let mut matches = Map::new();
        for item in &directive.block {
            match item.name.as_str() {
                "gzip" => {
                    let mut options = Map::new();
                    if let Some(level) = item.args.first() {
                        let level: u32 = level.parse().map_err(|_| {
                            adapter_error(
                                item.position,
                                format!("gzip level `{level}` is not a number"),
                            )
                        })?;
                        options.insert("level".to_string(), json!(level));
                    }
                    encodings.insert("gzip".to_string(), Value::Object(options));
                    prefer.push(json!("gzip"));
                }
                "zstd" => {
                    let mut options = Map::new();
                    for option in &item.block {
                        if option.name == "disable_checksum" {
                            options.insert("checksum".to_string(), json!(false));
                        } else {
                            return Err(adapter_error(
                                option.position,
                                format!("unsupported zstd option `{}`", option.name),
                            ));
                        }
                    }
                    encodings.insert("zstd".to_string(), Value::Object(options));
                    prefer.push(json!("zstd"));
                }
                "minimum_length" => {
                    let Some(value) = item.args.first() else {
                        return Err(adapter_error(
                            item.position,
                            "`minimum_length` requires a value",
                        ));
                    };
                    minimum_length = Some(json!(parse_size(value)
                        .map_err(|message| { adapter_error(item.position, message) })?));
                }
                "match" => {
                    for matcher in &item.block {
                        match matcher.name.as_str() {
                            "status" => {
                                let mut codes = Vec::new();
                                for code in &matcher.args {
                                    codes.push(parse_status_range(code).map_err(|message| {
                                        adapter_error(matcher.position, message)
                                    })?);
                                }
                                matches.insert("status_code".to_string(), json!(codes));
                            }
                            "header" => {
                                let Some(field) = matcher.args.first() else {
                                    return Err(adapter_error(
                                        matcher.position,
                                        "`match header` requires a field",
                                    ));
                                };
                                let mut values = Vec::new();
                                for value in matcher.args.iter().skip(1) {
                                    values.push(json!(value));
                                }
                                let headers = matches
                                    .entry("headers".to_string())
                                    .or_insert_with(|| json!({}));
                                if let Some(headers) = headers.as_object_mut() {
                                    headers.insert(field.clone(), json!(values));
                                }
                            }
                            other => {
                                return Err(adapter_error(
                                    matcher.position,
                                    format!("unsupported encode match `{other}`"),
                                ))
                            }
                        }
                    }
                }
                other => {
                    return Err(adapter_error(
                        item.position,
                        format!("unsupported `encode` option `{other}`"),
                    ))
                }
            }
        }
        if encodings.is_empty() {
            encodings.insert("zstd".to_string(), json!({}));
            encodings.insert("gzip".to_string(), json!({}));
            prefer.extend([json!("zstd"), json!("gzip")]);
        }
        if !matches.is_empty() {
            // Keep for callers that build the handler object below.
        }
        let mut object = Map::new();
        object.insert("handler".to_string(), json!("encode"));
        object.insert("encodings".to_string(), Value::Object(encodings));
        object.insert("prefer".to_string(), Value::Array(prefer));
        if let Some(minimum_length) = minimum_length {
            object.insert("minimum_length".to_string(), minimum_length);
        }
        if !matches.is_empty() {
            object.insert("match".to_string(), Value::Object(matches));
        }
        return Ok(Value::Object(object));
    }

    Ok(json!({
        "handler": "encode",
        "encodings": Value::Object(encodings),
        "prefer": prefer,
    }))
}

fn reverse_proxy_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    if args.is_empty() {
        return Err(adapter_error(
            directive.position,
            "`reverse_proxy` requires at least one upstream",
        ));
    }
    let mut upstreams = Vec::new();
    let mut https_target = false;
    let mut extra_transport = Map::new();
    for target in args {
        let parsed = parse_upstream(target).map_err(|message| {
            adapter_error(
                directive.position,
                format!("upstream `{target}`: {message}"),
            )
        })?;
        https_target |= parsed.https;
        upstreams.push(json!({"dial": parsed.dial}));
    }

    let mut object = Map::new();
    object.insert("handler".to_string(), json!("reverse_proxy"));
    object.insert("upstreams".to_string(), Value::Array(upstreams));

    let mut load_balancing = Map::new();
    let mut request_headers = Map::new();
    let mut response_headers = Map::new();
    let mut retry_match: Vec<Value> = Vec::new();

    for item in &directive.block {
        match item.name.as_str() {
            "lb_policy" => {
                let Some(policy) = item.args.first() else {
                    return Err(adapter_error(item.position, "`lb_policy` requires a value"));
                };
                load_balancing.insert("selection_policy".to_string(), json!({"policy": policy}));
            }
            "lb_retries" => {
                let Some(retries) = item.args.first() else {
                    return Err(adapter_error(
                        item.position,
                        "`lb_retries` requires a value",
                    ));
                };
                let retries: u32 = retries.parse().map_err(|_| {
                    adapter_error(
                        item.position,
                        format!("`lb_retries` value `{retries}` is not a number"),
                    )
                })?;
                load_balancing.insert("retries".to_string(), json!(retries));
            }
            "lb_try_duration" => {
                let Some(duration) = item.args.first() else {
                    return Err(adapter_error(
                        item.position,
                        "`lb_try_duration` requires a value",
                    ));
                };
                let nanos = parse_duration(duration)
                    .map_err(|message| adapter_error(item.position, message))?;
                load_balancing.insert("try_duration".to_string(), json!(nanos));
            }
            "lb_try_interval" => {
                let Some(duration) = item.args.first() else {
                    return Err(adapter_error(
                        item.position,
                        "`lb_try_interval` requires a value",
                    ));
                };
                let nanos = parse_duration(duration)
                    .map_err(|message| adapter_error(item.position, message))?;
                load_balancing.insert("try_interval".to_string(), json!(nanos));
            }
            "lb_retry_match" => {
                let matcher = if item.block.is_empty() {
                    let Some(name) = item.args.first() else {
                        return Err(adapter_error(
                            item.position,
                            "`lb_retry_match` requires a matcher",
                        ));
                    };
                    matcher_from_directive(name, &item.args[1..], item.position)?
                } else {
                    matcher_from_directives(&item.block)?
                };
                retry_match.push(matcher);
            }
            "header_up" => {
                if item.args.len() < 2 {
                    return Err(adapter_error(
                        item.position,
                        "`header_up` requires a field and value",
                    ));
                }
                request_headers.insert(
                    item.args[0].clone(),
                    json!([rewrite_placeholder(&item.args[1..].join(" "))]),
                );
            }
            "header_down" => {
                if item.args.len() < 2 {
                    return Err(adapter_error(
                        item.position,
                        "`header_down` requires a field and value",
                    ));
                }
                response_headers.insert(
                    item.args[0].clone(),
                    json!([rewrite_placeholder(&item.args[1..].join(" "))]),
                );
            }
            "request_buffers" => {
                let Some(value) = item.args.first() else {
                    return Err(adapter_error(
                        item.position,
                        "`request_buffers` requires a value",
                    ));
                };
                object.insert(
                    "request_buffers".to_string(),
                    json!(parse_buffer_size(value)
                        .map_err(|message| adapter_error(item.position, message))?),
                );
            }
            "response_buffers" => {
                let Some(value) = item.args.first() else {
                    return Err(adapter_error(
                        item.position,
                        "`response_buffers` requires a value",
                    ));
                };
                object.insert(
                    "response_buffers".to_string(),
                    json!(parse_buffer_size(value)
                        .map_err(|message| adapter_error(item.position, message))?),
                );
            }
            "transport" => {
                if item.args.first().map(String::as_str) != Some("http") {
                    return Err(adapter_error(
                        item.position,
                        "only `transport http` is supported by this build",
                    ));
                }
                for option in &item.block {
                    match option.name.as_str() {
                        "tls" => {
                            extra_transport.insert("tls".to_string(), json!({}));
                        }
                        "tls_insecure_skip_verify" => {
                            let tls = extra_transport
                                .entry("tls".to_string())
                                .or_insert_with(|| json!({}));
                            if let Some(tls) = tls.as_object_mut() {
                                tls.insert("insecure_skip_verify".to_string(), json!(true));
                            }
                        }
                        other => {
                            return Err(adapter_error(
                                option.position,
                                format!(
                                    "transport option `{other}` is not supported by this build"
                                ),
                            ))
                        }
                    }
                }
            }
            other => {
                return Err(adapter_error(
                    item.position,
                    format!("`reverse_proxy` option `{other}` is not supported by this build"),
                ))
            }
        }
    }

    if !load_balancing.is_empty() {
        if !retry_match.is_empty() {
            load_balancing.insert("retry_match".to_string(), Value::Array(retry_match));
        }
        object.insert("load_balancing".to_string(), Value::Object(load_balancing));
    }
    if !request_headers.is_empty() || !response_headers.is_empty() {
        let mut headers = Map::new();
        if !request_headers.is_empty() {
            headers.insert(
                "request".to_string(),
                json!({"set": Value::Object(request_headers)}),
            );
        }
        if !response_headers.is_empty() {
            headers.insert(
                "response".to_string(),
                json!({"set": Value::Object(response_headers)}),
            );
        }
        object.insert("headers".to_string(), Value::Object(headers));
    }
    if https_target {
        let mut transport = Map::new();
        transport.insert("protocol".to_string(), json!("http"));
        transport.insert(
            "tls".to_string(),
            Value::Object(
                extra_transport
                    .remove("tls")
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default(),
            ),
        );
        object.insert("transport".to_string(), Value::Object(transport));
    } else if !extra_transport.is_empty() {
        let mut transport = Map::new();
        transport.insert("protocol".to_string(), json!("http"));
        transport.extend(extra_transport);
        object.insert("transport".to_string(), Value::Object(transport));
    }
    Ok(Value::Object(object))
}

struct ParsedUpstream {
    dial: String,
    https: bool,
}

fn parse_upstream(target: &str) -> Result<ParsedUpstream, String> {
    let (scheme, rest) = match target.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, target),
    };
    if let Some(scheme) = scheme {
        if !matches!(scheme, "http" | "https" | "h2c") {
            return Err(format!("unsupported scheme `{scheme}://`"));
        }
    }
    // Strip a path suffix for URL-style upstreams; Caddy's dial address is host:port.
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err("missing host".to_string());
    }
    Ok(ParsedUpstream {
        dial: authority.to_string(),
        https: scheme == Some("https"),
    })
}

fn rewrite_placeholder(value: &str) -> String {
    // Caddy expands short placeholders to fully qualified Caddy placeholders in adapted JSON.
    let mut out = value.to_string();
    for (short, full) in [
        ("{host}", "{http.request.host}"),
        ("{uri}", "{http.request.uri}"),
        ("{path}", "{http.request.uri.path}"),
        ("{method}", "{http.request.method}"),
        ("{scheme}", "{http.request.scheme}"),
        ("{remote_host}", "{http.request.remote.host}"),
        (
            "{upstream_hostport}",
            "{http.reverse_proxy.upstream.hostport}",
        ),
    ] {
        out = out.replace(short, full);
    }
    out
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let (number, unit) = split_number_unit(value)?;
    let multiplier: u64 = match unit {
        "ns" | "" => 1,
        "us" | "µs" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        other => return Err(format!("unknown duration unit `{other}`")),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration `{value}` overflows"))
}

fn parse_size(value: &str) -> Result<u64, String> {
    let (number, unit) = split_number_unit(value)?;
    let multiplier: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "kib" => 1_024,
        "mib" => 1_048_576,
        "gib" => 1_073_741_824,
        other => return Err(format!("unknown size unit `{other}`")),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size `{value}` overflows"))
}

fn parse_buffer_size(value: &str) -> Result<i64, String> {
    if value == "unlimited" {
        return Ok(-1);
    }
    let size = parse_size(value)?;
    i64::try_from(size).map_err(|_| format!("buffer size `{value}` is too large"))
}

fn split_number_unit(value: &str) -> Result<(u64, &str), String> {
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    if number.is_empty() {
        return Err(format!("missing numeric value in `{value}`"));
    }
    let number: u64 = number
        .parse()
        .map_err(|_| format!("invalid numeric value in `{value}`"))?;
    Ok((number, unit))
}

fn parse_status_range(value: &str) -> Result<u16, String> {
    if let Some(stripped) = value.strip_suffix("xx") {
        let class: u16 = stripped
            .parse()
            .map_err(|_| format!("invalid status range `{value}`"))?;
        Ok(class)
    } else {
        value
            .parse()
            .map_err(|_| format!("invalid status code `{value}`"))
    }
}

fn parse_error(error: parser::ParseError) -> CoreError {
    match error {
        parser::ParseError::Lex(error) => CoreError::invalid(
            format!("Caddyfile line {}", error.position.line),
            error.message,
        ),
        parser::ParseError::Syntax { position, message } => {
            CoreError::invalid(format!("Caddyfile line {}", position.line), message)
        }
    }
}

fn adapter_error(position: Position, message: impl Into<String>) -> CoreError {
    CoreError::invalid(format!("Caddyfile line {}", position.line), message)
}
