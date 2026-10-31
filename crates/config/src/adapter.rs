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

use caddy_rs_core::{AdaptedConfig, ConfigAdapter, Error as CoreError};
use serde_json::{json, Map, Value};

use crate::lexer::Position;
use crate::parser::{self, AutoHttpsMode, Directive, SiteBlock};

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

    // Each site block's route list is built once; a block may be served on several listeners.
    let mut site_routes: Vec<Vec<Value>> = Vec::with_capacity(file.sites.len());
    for site in &file.sites {
        site_routes.push(build_site_routes(site, &mut warnings)?);
    }

    // Assign each site address to the server (listener) that serves it. Caddy groups site blocks
    // per listener address; `bind` is not supported, so the listener is the wildcard address for
    // the address's effective port.
    let mut seen_addresses: BTreeMap<String, Position> = BTreeMap::new();
    let mut servers: Vec<ServerBuilder> = Vec::new();
    for (site_index, site) in file.sites.iter().enumerate() {
        let mut addresses_by_listener: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (address_index, address) in site.addresses.iter().enumerate() {
            let normalized = format!(
                "{}://{}:{}",
                address.scheme.as_deref().unwrap_or("auto"),
                address.host,
                address.effective_port(http_port, https_port)
            );
            if let Some(previous) = seen_addresses.insert(normalized, site.position) {
                return Err(adapter_error(
                    site.position,
                    format!(
                        "ambiguous site definition for address `{}` (first defined at {previous})",
                        address.raw
                    ),
                ));
            }
            let port = address.effective_port(http_port, https_port);
            let listen = listen_address(port);
            let https = address.is_https(http_port, https_port);
            let index = match servers.iter().position(|server| server.listen == listen) {
                Some(index) => index,
                None => {
                    servers.push(ServerBuilder {
                        listen: listen.clone(),
                        blocks: Vec::new(),
                        https,
                        skip_auto_https: Vec::new(),
                    });
                    servers.len() - 1
                }
            };
            let server = &mut servers[index];
            server.https |= https;
            if address.scheme.as_deref() == Some("http")
                && port != http_port
                && !address.host.is_empty()
            {
                let host = address.host.trim_start_matches('[').trim_end_matches(']');
                if !server.skip_auto_https.iter().any(|skip| skip == host) {
                    server.skip_auto_https.push(host.to_string());
                }
            }
            addresses_by_listener
                .entry(listen)
                .or_default()
                .push(address_index);
        }
        for (listen, address_indices) in addresses_by_listener {
            let server = servers
                .iter_mut()
                .find(|server| server.listen == listen)
                .expect("listener was registered above");
            server.blocks.push(SiteBlockPlan {
                site_index,
                address_indices,
            });
        }
    }

    // Caddy names servers ("srv0", ...) in sorted listener-address order.
    servers.sort_by(|left, right| left.listen.cmp(&right.listen));

    let mut server_map = Map::new();
    for (index, mut server) in servers.into_iter().enumerate() {
        sort_site_blocks(&mut server.blocks, &file.sites);
        let block_count = server.blocks.len();
        let mut routes = Vec::new();
        for block in &server.blocks {
            let site = &file.sites[block.site_index];
            let block_routes = site_routes[block.site_index].clone();
            let catch_all = block
                .address_indices
                .iter()
                .any(|address_index| site.addresses[*address_index].host.is_empty());
            let mut hosts: Vec<String> = Vec::new();
            if !catch_all {
                for address_index in &block.address_indices {
                    let host = site.addresses[*address_index]
                        .host
                        .trim_start_matches('[')
                        .trim_end_matches(']');
                    if !hosts.iter().any(|existing| existing == host) {
                        hosts.push(host.to_string());
                    }
                }
            }
            let matchers = if hosts.is_empty() {
                None
            } else {
                Some(json!([{"host": hosts}]))
            };
            // A site block with a hostless key has no host matcher (the hostless key already
            // matches every host), and Caddy does not wrap the sole catch-all block of a server
            // in a subroute unless one of its own routes carries a host matcher (issue #5124).
            let wrap = !(matchers.is_none()
                && block_count == 1
                && !routes_have_host_matcher(&block_routes));
            if wrap {
                let mut route = Map::new();
                if let Some(matchers) = matchers {
                    route.insert("match".to_string(), matchers);
                }
                if !block_routes.is_empty() {
                    route.insert(
                        "handle".to_string(),
                        json!([{"handler": "subroute", "routes": block_routes}]),
                    );
                }
                route.insert("terminal".to_string(), json!(true));
                if route.contains_key("match") || route.contains_key("handle") {
                    routes.push(Value::Object(route));
                }
            } else {
                routes.extend(block_routes);
            }
        }
        let routes = consolidate_routes(routes);

        let mut object = Map::new();
        object.insert("listen".to_string(), json!([server.listen]));
        let mut automatic_https = Map::new();
        match options.auto_https {
            Some(AutoHttpsMode::Off) => {
                automatic_https.insert("disable".to_string(), json!(true));
            }
            Some(AutoHttpsMode::DisableRedirects) => {
                automatic_https.insert("disable_redirects".to_string(), json!(true));
            }
            Some(AutoHttpsMode::IgnoreLoadedCerts) => {
                automatic_https.insert("ignore_loaded_certificates".to_string(), json!(true));
            }
            None => {}
        }
        if !server.skip_auto_https.is_empty() {
            automatic_https.insert("skip".to_string(), json!(server.skip_auto_https));
        }
        if !automatic_https.is_empty() {
            object.insert(
                "automatic_https".to_string(),
                Value::Object(automatic_https),
            );
        }
        if server.https && auto_https_off {
            object.insert("tls_connection_policies".to_string(), json!([{}]));
        }
        object.insert("routes".to_string(), Value::Array(routes));
        server_map.insert(format!("srv{index}"), Value::Object(object));
    }

    let mut apps = Map::new();
    apps.insert(
        "http".to_string(),
        json!({"servers": Value::Object(server_map)}),
    );
    if let Some(tls) = tls_app(&file.sites, http_port, auto_https_off)? {
        apps.insert("tls".to_string(), tls);
    }

    Ok(AdaptedConfig {
        config: json!({"apps": Value::Object(apps)}),
        warnings,
    })
}

struct ServerBuilder {
    listen: String,
    blocks: Vec<SiteBlockPlan>,
    https: bool,
    skip_auto_https: Vec<String>,
}

/// One site block as served by one listener: the block's routes plus which of its addresses are
/// bound to that listener.
struct SiteBlockPlan {
    site_index: usize,
    address_indices: Vec<usize>,
}

fn listen_address(port: u16) -> String {
    // Caddy site addresses name virtual hosts, not bind addresses; binding is controlled by the
    // `bind` directive. All sites therefore listen on the wildcard address for their port.
    format!(":{port}")
}

/// Sort site blocks the way Caddy's `httptype.go` does: descending host specificity, catch-all
/// blocks last, blocks with wildcard hosts after blocks with only concrete hosts.
fn sort_site_blocks(blocks: &mut [SiteBlockPlan], sites: &[SiteBlock]) {
    fn longest_host(block: &SiteBlockPlan, sites: &[SiteBlock]) -> (usize, bool) {
        let site = &sites[block.site_index];
        let mut longest = 0;
        let mut wildcard = false;
        for address_index in &block.address_indices {
            let address = &site.addresses[*address_index];
            if address.host.contains('*') || address.host.is_empty() {
                wildcard = true;
            }
            longest = longest.max(specificity(&address.host));
        }
        (longest, wildcard)
    }

    blocks.sort_by(|left, right| {
        let (left_host, left_wildcard) = longest_host(left, sites);
        let (right_host, right_wildcard) = longest_host(right, sites);
        let left_before = if left_host == 0 {
            false
        } else if right_host == 0 {
            true
        } else if left_wildcard != right_wildcard {
            right_wildcard && !left_wildcard
        } else {
            left_host > right_host
        };
        let right_before = if right_host == 0 {
            false
        } else if left_host == 0 {
            true
        } else if left_wildcard != right_wildcard {
            left_wildcard && !right_wildcard
        } else {
            right_host > left_host
        };
        if left_before {
            std::cmp::Ordering::Less
        } else if right_before {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

/// Caddy's address specificity: length with wildcards and placeholders removed.
fn specificity(value: &str) -> usize {
    let mut length = value.len() - value.matches('*').count();
    let mut rest = value;
    loop {
        let Some(start) = rest.find('{') else {
            return length;
        };
        let Some(relative_end) = rest[start..].find('}') else {
            return length;
        };
        let end = start + relative_end + 1;
        length -= end - start;
        rest = &rest[end..];
    }
}

fn routes_have_host_matcher(routes: &[Value]) -> bool {
    routes.iter().any(|route| {
        route
            .get("match")
            .and_then(Value::as_array)
            .map(|matcher_sets| {
                matcher_sets
                    .iter()
                    .any(|matcher_set| matcher_set.get("host").is_some())
            })
            .unwrap_or(false)
    })
}

/// Caddy's `consolidateRoutes`: merge adjacent routes with identical matchers, terminal flag and
/// group by concatenating their handler lists.
fn consolidate_routes(routes: Vec<Value>) -> Vec<Value> {
    let mut output: Vec<Value> = Vec::with_capacity(routes.len());
    for route in routes {
        if let Some(previous) = output.last_mut() {
            if routes_are_mergeable(previous, &route) {
                let mut handlers = previous
                    .get("handle")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if let Some(incoming) = route.get("handle").and_then(Value::as_array) {
                    handlers.extend(incoming.iter().cloned());
                }
                previous["handle"] = Value::Array(handlers);
                continue;
            }
        }
        output.push(route);
    }
    output
}

fn routes_are_mergeable(left: &Value, right: &Value) -> bool {
    left.get("match") == right.get("match")
        && left
            .get("terminal")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            == right
                .get("terminal")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        && left.get("group") == right.get("group")
}

/// Build the `apps.tls` section Caddy's adapter emits for automatic HTTPS.
///
/// Hostnames that share a site block with a hostless key never appear in a route matcher, so
/// Caddy adds them to `certificates.automate` explicitly instead of relying on route-derived
/// automatic HTTPS.
fn tls_app(
    sites: &[SiteBlock],
    http_port: u16,
    auto_https_off: bool,
) -> caddy_rs_core::Result<Option<Value>> {
    if auto_https_off {
        return Ok(None);
    }
    let mut automate: Vec<String> = Vec::new();
    for site in sites {
        if !site.addresses.iter().any(|address| address.host.is_empty()) {
            continue;
        }
        for address in &site.addresses {
            if address.host.is_empty()
                || address.scheme.as_deref() == Some("http")
                || address.port == Some(http_port)
            {
                continue;
            }
            let host = address
                .host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            if !subject_qualifies_for_public_cert(&host) {
                return Err(adapter_error(
                    site.position,
                    format!(
                        "automatic HTTPS for internal name `{host}` shared with a hostless site \
                         address is not supported by this build"
                    ),
                ));
            }
            if !automate.contains(&host) {
                automate.push(host);
            }
        }
    }
    if automate.is_empty() {
        return Ok(None);
    }
    automate.sort();
    Ok(Some(json!({"certificates": {"automate": automate}})))
}

/// Approximation of `certmagic.SubjectQualifiesForPublicCert` for the names Caddy's adapter must
/// list explicitly: internal names are not publicly issuable.
fn subject_qualifies_for_public_cert(subject: &str) -> bool {
    if subject.is_empty() {
        return false;
    }
    if subject == "localhost"
        || subject.ends_with(".localhost")
        || subject.ends_with(".local")
        || subject.ends_with(".internal")
        || subject.ends_with(".home.arpa")
    {
        return false;
    }
    subject.parse::<std::net::IpAddr>().is_err()
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
        let mut object = if directive.block.is_empty() {
            matcher_from_inline_args(&directive.args, directive.position)?
        } else {
            matcher_from_directives(&directive.block)?
        };
        if let Some(regexp) = object.get_mut("path_regexp").and_then(Value::as_object_mut) {
            regexp
                .entry("name".to_string())
                .or_insert_with(|| json!(name));
        }
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
    let mut ordered: Vec<&Directive> = Vec::new();
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
        ordered.push(directive);
    }

    if sort {
        ordered.sort_by_key(|directive| {
            // Caddy normalises `handle_path` to `handle` before sorting so both share a slot.
            let name = if directive.name == "handle_path" {
                "handle"
            } else {
                directive.name.as_str()
            };
            DIRECTIVE_ORDER
                .iter()
                .position(|candidate| *candidate == name)
                .unwrap_or(usize::MAX)
        });
    }

    // Caddy puts multiple mutually-exclusive `handle`/`handle_path` routes in one group.
    let handle_count = ordered
        .iter()
        .filter(|directive| matches!(directive.name.as_str(), "handle" | "handle_path"))
        .count();

    let mut entries: Vec<(&str, Value)> = Vec::new();
    for directive in ordered {
        let name = directive.name.as_str();
        match name {
            "route" => {
                let inner = build_routes(&directive.block, matchers, false, warnings)?;
                if inner.is_empty() {
                    entries.push((name, json!({"handle": [{"handler": "subroute"}]})));
                } else {
                    entries.push((
                        name,
                        json!({"handle": [{"handler": "subroute", "routes": inner}]}),
                    ));
                }
            }
            "handle" | "handle_path" => {
                let mut route = build_handle_route(directive, matchers, warnings)?;
                if handle_count > 1 {
                    route["group"] = json!("group1");
                }
                entries.push((name, route));
            }
            _ => {
                let mut args = directive.args.clone();
                let matcher = matcher_for_args(&mut args, matchers, directive.position)?;
                let handlers = build_handlers(directive, &args, warnings)?;
                if handlers.is_empty() {
                    continue;
                }
                let route = match matcher {
                    Some(matcher) => json!({
                        "match": [matcher],
                        "handle": handlers,
                    }),
                    None => json!({"handle": handlers}),
                };
                entries.push((name, route));
            }
        }
    }

    if sort {
        entries.sort_by(|left, right| {
            let left_position = directive_position(left.0);
            let right_position = directive_position(right.0);
            if left_position != right_position {
                return left_position.cmp(&right_position);
            }
            route_path_order(&left.1, &right.1)
        });
    }

    Ok(consolidate_routes(
        entries.into_iter().map(|(_, route)| route).collect(),
    ))
}

fn directive_position(name: &str) -> usize {
    let name = if name == "handle_path" {
        "handle"
    } else {
        name
    };
    DIRECTIVE_ORDER
        .iter()
        .position(|candidate| *candidate == name)
        .unwrap_or(usize::MAX)
}

/// Caddy's `sortRoutes` sub-ordering for two routes of the same directive: more specific paths
/// first, a trailing wildcard last among equal prefixes, then lexical order; routes with any
/// matcher come before routes with none.
fn route_path_order(left: &Value, right: &Value) -> std::cmp::Ordering {
    fn less(left: &Value, right: &Value) -> bool {
        let left_path = single_path(left);
        let right_path = single_path(right);
        let left_length = left_path.map(str::len).unwrap_or(0);
        let right_length = right_path.map(str::len).unwrap_or(0);
        if left_length > 0 && right_length > 0 {
            let left_path = left_path.expect("length checked");
            let right_path = right_path.expect("length checked");
            let left_trimmed = left_path.trim_end_matches('*');
            let right_trimmed = right_path.trim_end_matches('*');
            if left_trimmed == right_trimmed {
                return left_length < right_length;
            }
            if left_trimmed.len() == right_trimmed.len() {
                return left_trimmed < right_trimmed;
            }
            return left_trimmed.len() > right_trimmed.len();
        }
        route_has_matchers(left) && !route_has_matchers(right)
    }

    if less(left, right) {
        std::cmp::Ordering::Less
    } else if less(right, left) {
        std::cmp::Ordering::Greater
    } else {
        std::cmp::Ordering::Equal
    }
}

fn single_path(route: &Value) -> Option<&str> {
    let matcher_sets = route.get("match")?.as_array()?;
    if matcher_sets.len() != 1 {
        return None;
    }
    let paths = matcher_sets[0].get("path")?.as_array()?;
    if paths.len() != 1 {
        return None;
    }
    paths[0].as_str()
}

fn route_has_matchers(route: &Value) -> bool {
    route
        .get("match")
        .and_then(Value::as_array)
        .map(|matcher_sets| !matcher_sets.is_empty())
        .unwrap_or(false)
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
        // Caddy matches the literal path given and strips everything but the trailing wildcard:
        // `/api/*` matches `/api/*` and strips `/api`; `/api` matches and strips `/api`.
        let strip = if let Some(base) = prefix.strip_suffix("/*") {
            base.to_string()
        } else if let Some(base) = prefix.strip_suffix('*') {
            base.to_string()
        } else {
            prefix.clone()
        };
        matcher = Some(json!({"path": [prefix]}));
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
        "respond" => vec![respond_handler(directive, args)?],
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

fn respond_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    let position = directive.position;
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("static_response"));

    // A `respond` block may override the body: `respond /path 200 { body "..." }`.
    let mut block_body: Option<String> = None;
    for item in &directive.block {
        match item.name.as_str() {
            "body" => {
                let body = item.args.join(" ");
                block_body = Some(body);
            }
            other => {
                return Err(adapter_error(
                    item.position,
                    format!("`respond` block option `{other}` is not supported by this build"),
                ))
            }
        }
    }

    let (body, status) = if let Some(body) = block_body {
        (Some(body), args.first().cloned())
    } else {
        match args {
            // `respond 403` is a status-only response in Caddy, not a body.
            [only] if is_status_code(only) => (None, Some(only.clone())),
            [body, status, ..] => (Some(body.clone()), Some(status.clone())),
            [body] => (Some(body.clone()), None),
            [] => (None, None),
        }
    };
    if let Some(body) = body {
        if !body.is_empty() {
            object.insert("body".to_string(), json!(qualify_placeholders(&body)));
        }
    }
    if let Some(status) = status {
        let code: u16 = status.parse().map_err(|_| {
            adapter_error(
                position,
                format!("`respond` status `{status}` is not a number"),
            )
        })?;
        object.insert("status_code".to_string(), json!(code));
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
        "headers": {"Location": [qualify_placeholders(location)]},
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
        if directive.args.len() >= 3 && !directive.args[0].starts_with(['+', '-', '?', '>']) {
            // `header <field> <search> <replacement>` is Caddy's regex replacement form.
            let replace = json!({
                "handler": "headers",
                "response": {
                    "replace": {
                        directive.args[0].clone(): [{
                            "search_regexp": qualify_placeholders(&directive.args[1]),
                            "replace": qualify_placeholders(&directive.args[2]),
                        }]
                    }
                }
            });
            return Ok(vec![replace]);
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
            adds.insert(
                name.to_string(),
                json!(values
                    .iter()
                    .map(|value| qualify_placeholders(value))
                    .collect::<Vec<_>>()),
            );
        } else if let Some(name) = field.strip_prefix('-') {
            deletes.push(Value::String(name.to_string()));
        } else if let Some(name) = field.strip_prefix('?') {
            sets.insert(
                name.to_string(),
                json!(values
                    .iter()
                    .map(|value| qualify_placeholders(value))
                    .collect::<Vec<_>>()),
            );
        } else {
            let values: Vec<String> = values
                .iter()
                .map(|value| qualify_placeholders(value))
                .collect();
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
    let mut hide: Vec<Value> = Vec::new();
    let mut index_names: Vec<Value> = Vec::new();

    fn apply_option(
        directive: &Directive,
        name: &str,
        values: &[String],
        block: &[Directive],
        object: &mut Map<String, Value>,
        hide: &mut Vec<Value>,
        index_names: &mut Vec<Value>,
    ) -> caddy_rs_core::Result<()> {
        match name {
            "browse" => {
                let mut browse = Map::new();
                for option in block {
                    match option.name.as_str() {
                        "sort" => {
                            if option.args.is_empty() {
                                return Err(adapter_error(
                                    option.position,
                                    "`browse sort` requires one or more fields",
                                ));
                            }
                            browse.insert("sort".to_string(), json!(option.args));
                        }
                        "file_limit" => {
                            if option.args.len() != 1 {
                                return Err(adapter_error(
                                    option.position,
                                    "`browse file_limit` requires exactly one integer",
                                ));
                            }
                            let limit: u64 = option.args[0].parse().map_err(|_| {
                                adapter_error(
                                    option.position,
                                    format!(
                                        "`browse file_limit` value `{}` is not an integer",
                                        option.args[0]
                                    ),
                                )
                            })?;
                            browse.insert("file_limit".to_string(), json!(limit));
                        }
                        other => {
                            return Err(adapter_error(
                                option.position,
                                format!("`browse` option `{other}` is not supported by this build"),
                            ))
                        }
                    }
                }
                if !values.is_empty() {
                    return Err(adapter_error(
                        directive.position,
                        "`browse` does not take inline arguments",
                    ));
                }
                object.insert("browse".to_string(), Value::Object(browse));
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
    }

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
        apply_option(
            directive,
            &name,
            &values,
            &[],
            &mut object,
            &mut hide,
            &mut index_names,
        )?;
    }

    // Options written in a nested block.
    for item in &directive.block {
        apply_option(
            directive,
            &item.name,
            &item.args,
            &item.block,
            &mut object,
            &mut hide,
            &mut index_names,
        )?;
    }

    // Caddy hides the config file itself by default, appended after any explicit hide entries.
    if !hide
        .iter()
        .any(|value| value.as_str() == Some("./Caddyfile"))
    {
        hide.push(json!("./Caddyfile"));
    }
    object.insert("hide".to_string(), Value::Array(hide));
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
                if !prefer.iter().any(|value| value == "gzip") {
                    prefer.push(json!("gzip"));
                }
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
                if !prefer.iter().any(|value| value == "zstd") {
                    prefer.push(json!("zstd"));
                }
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
                                codes.push(
                                    parse_status_range(code).map_err(|message| {
                                        adapter_error(matcher.position, message)
                                    })?,
                                );
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
                            let values: Vec<Value> = matcher
                                .args
                                .iter()
                                .skip(1)
                                .map(|value| json!(value))
                                .collect();
                            let headers = matches
                                .entry("headers".to_string())
                                .or_insert_with(|| json!({}));
                            if let Some(headers) = headers.as_object_mut() {
                                match headers.get_mut(field) {
                                    Some(Value::Array(existing)) => existing.extend(values),
                                    _ => {
                                        headers.insert(field.clone(), json!(values));
                                    }
                                }
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
    Ok(Value::Object(object))
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
    let mut h2c_target = false;
    let mut extra_transport = Map::new();
    for target in args {
        let parsed = parse_upstream(target).map_err(|message| {
            adapter_error(
                directive.position,
                format!("upstream `{target}`: {message}"),
            )
        })?;
        https_target |= parsed.https;
        h2c_target |= parsed.h2c;
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
                let mut selection = Map::new();
                selection.insert("policy".to_string(), json!(policy));
                if item.args.len() > 1 {
                    let mut weights = Vec::new();
                    for weight in item.args.iter().skip(1) {
                        let weight: u64 = weight.parse().map_err(|_| {
                            adapter_error(
                                item.position,
                                format!("`lb_policy` weight `{weight}` is not a number"),
                            )
                        })?;
                        weights.push(json!(weight));
                    }
                    selection.insert("weights".to_string(), json!(weights));
                }
                load_balancing.insert("selection_policy".to_string(), Value::Object(selection));
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
                    json!([qualify_placeholders(&item.args[1..].join(" "))]),
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
                    json!([qualify_placeholders(&item.args[1..].join(" "))]),
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
    if https_target || h2c_target || !extra_transport.is_empty() {
        let mut transport = Map::new();
        transport.insert("protocol".to_string(), json!("http"));
        if https_target {
            transport.insert(
                "tls".to_string(),
                Value::Object(
                    extra_transport
                        .remove("tls")
                        .and_then(|v| v.as_object().cloned())
                        .unwrap_or_default(),
                ),
            );
        } else {
            transport.extend(extra_transport);
        }
        if h2c_target {
            transport.insert("versions".to_string(), json!(["h2c", "2"]));
        }
        object.insert("transport".to_string(), Value::Object(transport));
    }
    Ok(Value::Object(object))
}

struct ParsedUpstream {
    dial: String,
    https: bool,
    h2c: bool,
}

fn parse_upstream(target: &str) -> Result<ParsedUpstream, String> {
    // Network-specific shorthand: `unix+h2c//path` means a Unix-socket upstream whose transport
    // speaks h2c, and Caddy normalises it to a `unix/...` dial plus an h2c transport.
    if let Some(rest) = target.strip_prefix("unix+h2c//") {
        return Ok(ParsedUpstream {
            dial: format!("unix//{rest}"),
            https: false,
            h2c: true,
        });
    }
    // Network addresses like `unix//path/to/socket` are passed through verbatim; Caddy's dial
    // string keeps the network prefix.
    if target.starts_with("unix//") {
        return Ok(ParsedUpstream {
            dial: target.to_string(),
            https: false,
            h2c: false,
        });
    }
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
    let default_port = if scheme == Some("https") { 443 } else { 80 };
    let dial = if authority_has_port(authority) {
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };
    Ok(ParsedUpstream {
        dial,
        https: scheme == Some("https"),
        h2c: scheme == Some("h2c"),
    })
}

fn authority_has_port(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(_, tail)| tail.starts_with(':'))
            .unwrap_or(false);
    }
    authority
        .rsplit_once(':')
        .map(|(_, port)| !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()))
        .unwrap_or(false)
}

/// Expand Caddy's shorthand placeholders to the fully qualified forms Caddy's adapter emits.
///
/// The runtime does not expand placeholders yet (DIV-0007); this keeps adapted JSON faithful to
/// Caddy so the compatibility layer can be tested independently of placeholder support.
fn qualify_placeholders(value: &str) -> String {
    let mut out = value.to_string();
    for (short, full) in [
        ("{re.", "{http.regexp."),
        ("{header.", "{http.request.header."),
        ("{labels.", "{http.request.host.labels."),
        ("{query.", "{http.request.uri.query."),
        ("{path.", "{http.request.uri.path."),
        ("{host}", "{http.request.host}"),
        ("{uri}", "{http.request.uri}"),
        ("{path}", "{http.request.uri.path}"),
        ("{method}", "{http.request.method}"),
        ("{scheme}", "{http.request.scheme}"),
        ("{remote_host}", "{http.request.remote.host}"),
        ("{remote_port}", "{http.request.remote.port}"),
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
