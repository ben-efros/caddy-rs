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

use std::collections::{BTreeMap, BTreeSet};

use caddy_rs_core::{AdaptedConfig, ConfigAdapter, Error as CoreError};
use serde_json::{json, Map, Value};

use crate::lexer::Position;
use crate::parser::{self, Directive, SiteBlock};

/// Canonical directive order, mirroring Caddy's default order for the supported subset.
const DIRECTIVE_ORDER: &[&str] = &[
    "map",
    "vars",
    "root",
    "header",
    "request_body",
    "redir",
    "method",
    "uri",
    "try_files",
    "basicauth",
    "basic_auth",
    "forward_auth",
    "encode",
    "invoke",
    "handle",
    "handle_path",
    "route",
    "respond",
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
    adapt_with_source(input, None)
}

/// Adapt a Caddyfile string to Caddy JSON, resolving file/glob imports relative to `source`.
pub fn adapt_with_source(
    input: &str,
    source: Option<&std::path::Path>,
) -> caddy_rs_core::Result<AdaptedConfig> {
    let file = parser::parse_with_source(input, source).map_err(parse_error)?;
    let options = &file.options;
    let http_port = options.http_port.unwrap_or(80);
    let https_port = options.https_port.unwrap_or(443);
    let mut warnings = options.warnings.clone();

    // Parse each block's `tls` directive once; the adapter builds routes and the TLS app from it.
    let site_tls: Vec<Option<SiteTls>> = file
        .sites
        .iter()
        .map(|site| parse_site_tls(site, source))
        .collect::<caddy_rs_core::Result<_>>()?;

    // Site-level `bind` and `log` directives configure the listener and server log association
    // rather than HTTP handlers; parse them before the routes so both can be emitted together.
    let site_binds: Vec<Vec<BindAddress>> = file
        .sites
        .iter()
        .map(parse_site_bind)
        .collect::<caddy_rs_core::Result<_>>()?;
    let site_logs: Vec<bool> = file
        .sites
        .iter()
        .map(parse_site_log)
        .collect::<caddy_rs_core::Result<_>>()?;

    // Named-route definitions are emitted as `named_routes` on each server that invokes them,
    // transitively (Caddy's `extractNamedRoutes`/`namedRouteInvokes`).
    let mut named_route_json: BTreeMap<String, Value> = BTreeMap::new();
    let mut named_route_invokes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for named in &file.named_routes {
        named_route_json.insert(named.name.clone(), build_named_route(named, &mut warnings)?);
        let mut invokes = Vec::new();
        collect_invoke_names(&named.directives, &mut invokes);
        named_route_invokes.insert(named.name.clone(), invokes);
    }

    // Each site block's route list is built once; a block may be served on several listeners.
    let mut site_routes: Vec<Vec<Value>> = Vec::with_capacity(file.sites.len());
    for site in &file.sites {
        site_routes.push(build_site_routes(site, &mut warnings)?);
    }

    // Assign each site address to the server (listener) that serves it. Caddy groups site blocks
    // per listener address: the wildcard address for the effective port unless `bind` overrides it.
    let mut listener_entries: BTreeMap<String, ListenerEntry> = BTreeMap::new();
    for (site_index, site) in file.sites.iter().enumerate() {
        for (address_index, address) in site.addresses.iter().enumerate() {
            let port = address.effective_port(http_port, https_port);
            // Without `bind` Caddy listens on the wildcard address for the site's port; with
            // `bind` each bind address becomes a listener for that port (and its protocols).
            let listeners: Vec<String> = if site_binds[site_index].is_empty() {
                vec![listen_address(port)]
            } else {
                let mut listeners: Vec<String> = Vec::new();
                for bind in &site_binds[site_index] {
                    let listen = join_bind_address(bind, port)?;
                    if !listeners.contains(&listen) {
                        listeners.push(listen);
                    }
                }
                listeners
            };
            for listen in listeners {
                let entry = listener_entries
                    .entry(listen)
                    .or_insert_with(|| ListenerEntry { keys: Vec::new() });
                let key = (site_index, address_index);
                if !entry.keys.contains(&key) {
                    entry.keys.push(key);
                }
            }
        }
    }

    // Caddy consolidates listeners that serve an identical set of keys (and protocols) into one
    // server; the server's listen list is the sorted listener addresses.
    let mut grouped: BTreeMap<Vec<(usize, usize)>, Vec<String>> = BTreeMap::new();
    for (listen, mut entry) in listener_entries {
        entry.keys.sort_unstable();
        grouped.entry(entry.keys).or_default().push(listen);
    }
    let mut servers: Vec<ServerBuilder> = Vec::new();
    for (keys, mut listens) in grouped {
        listens.sort();
        // Caddy rejects two site blocks that define the same key on the same listener set.
        let mut seen_keys: BTreeMap<String, Position> = BTreeMap::new();
        for (site_index, address_index) in &keys {
            let site = &file.sites[*site_index];
            let address = &site.addresses[*address_index];
            let normalized = format!(
                "{}://{}:{}",
                address.scheme.as_deref().unwrap_or("auto"),
                address.host,
                address.effective_port(http_port, https_port)
            );
            if let Some(previous) = seen_keys.insert(normalized, site.position) {
                return Err(adapter_error(
                    site.position,
                    format!(
                        "ambiguous site definition for address `{}` (first defined at {previous})",
                        address.raw
                    ),
                ));
            }
        }
        let mut blocks: Vec<SiteBlockPlan> = Vec::new();
        for (site_index, address_index) in keys {
            match blocks
                .iter_mut()
                .find(|block| block.site_index == site_index)
            {
                Some(block) => block.address_indices.push(address_index),
                None => blocks.push(SiteBlockPlan {
                    site_index,
                    address_indices: vec![address_index],
                }),
            }
        }
        let mut https = false;
        let mut skip_auto_https: Vec<String> = Vec::new();
        for block in &blocks {
            let site = &file.sites[block.site_index];
            for address_index in &block.address_indices {
                let address = &site.addresses[*address_index];
                https |= address.is_https(http_port, https_port);
                let port = address.effective_port(http_port, https_port);
                if address.scheme.as_deref() == Some("http")
                    && port != http_port
                    && !address.host.is_empty()
                {
                    let host = address.host.trim_start_matches('[').trim_end_matches(']');
                    if !skip_auto_https.iter().any(|skip| skip == host) {
                        skip_auto_https.push(host.to_string());
                    }
                }
            }
        }
        servers.push(ServerBuilder {
            listens,
            blocks,
            https,
            skip_auto_https,
        });
    }

    // Caddy names servers ("srv0", ...) in sorted listener-address order.
    servers.sort_by(|left, right| left.listens.cmp(&right.listens));

    // Caddy sorts the server blocks of each listener once, before building both routes and TLS.
    for server in &mut servers {
        sort_site_blocks(&mut server.blocks, &file.sites);
    }
    let tls_plan = build_tls_plan(&file, &site_tls, &servers, http_port, https_port)?;

    let mut server_map = Map::new();
    for (index, server) in servers.into_iter().enumerate() {
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

        // Named routes reachable from this server's site blocks, transitively.
        let mut attached: Vec<String> = Vec::new();
        for block in &server.blocks {
            collect_invoke_names(&file.sites[block.site_index].directives, &mut attached);
        }
        let mut attached_index = 0;
        while attached_index < attached.len() {
            if let Some(invokes) = named_route_invokes.get(&attached[attached_index]) {
                for name in invokes {
                    if !attached.contains(name) {
                        attached.push(name.clone());
                    }
                }
            }
            attached_index += 1;
        }
        let attached: BTreeMap<String, Value> = attached
            .into_iter()
            .filter_map(|name| {
                named_route_json
                    .get(&name)
                    .map(|route| (name.clone(), route.clone()))
            })
            .collect();

        let mut object = Map::new();
        object.insert("listen".to_string(), json!(server.listens));
        let mut automatic_https = Map::new();
        if options.auto_https.off {
            automatic_https.insert("disable".to_string(), json!(true));
        }
        if options.auto_https.disable_redirects {
            automatic_https.insert("disable_redirects".to_string(), json!(true));
        }
        if options.auto_https.disable_certs {
            automatic_https.insert("disable_certificates".to_string(), json!(true));
        }
        if options.auto_https.ignore_loaded_certs {
            automatic_https.insert("ignore_loaded_certificates".to_string(), json!(true));
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
        if let Some(connection_policies) = tls_plan.connection_policies.get(index) {
            if !connection_policies.is_empty() {
                object.insert(
                    "tls_connection_policies".to_string(),
                    Value::Array(connection_policies.clone()),
                );
            }
        }
        if !routes.is_empty() {
            object.insert("routes".to_string(), Value::Array(routes));
        }
        if !attached.is_empty() {
            object.insert("named_routes".to_string(), json!(attached));
        }
        if let Some(logs) = build_server_logs(&file, &server, &site_logs) {
            object.insert("logs".to_string(), logs);
        }
        server_map.insert(format!("srv{index}"), Value::Object(object));
    }
    let mut apps = Map::new();
    // Caddy's caddyhttp.App carries the global HTTP/HTTPS ports (used for automatic-HTTPS
    // redirects and ACME challenge ports); they are emitted only when explicitly configured.
    let mut http_app = Map::new();
    if let Some(port) = options.http_port {
        http_app.insert("http_port".to_string(), json!(port));
    }
    if let Some(port) = options.https_port {
        http_app.insert("https_port".to_string(), json!(port));
    }
    http_app.insert("servers".to_string(), Value::Object(server_map));
    apps.insert("http".to_string(), Value::Object(http_app));
    if let Some(tls) = tls_plan.app.clone() {
        apps.insert("tls".to_string(), tls);
    }
    if let Some(pki) = pki_app_json(options) {
        apps.insert("pki".to_string(), pki);
    }

    Ok(AdaptedConfig {
        config: json!({"apps": Value::Object(apps)}),
        warnings,
    })
}

struct ServerBuilder {
    /// Listen addresses sorted as Caddy's paired address list.
    listens: Vec<String>,
    blocks: Vec<SiteBlockPlan>,
    https: bool,
    skip_auto_https: Vec<String>,
}

/// One listener address and the site address keys it serves.
struct ListenerEntry {
    keys: Vec<(usize, usize)>,
}

/// One site block as served by one listener: the block's routes plus which of its addresses are
/// bound to that listener.
struct SiteBlockPlan {
    site_index: usize,
    address_indices: Vec<usize>,
}

fn listen_address(port: u16) -> String {
    // Without a `bind` directive Caddy listens on the wildcard address for the site's port.
    format!(":{port}")
}

/// One `bind` address: optional network prefix (`tcp`, `tcp4`, `tcp6`) and host.
struct BindAddress {
    network: String,
    host: String,
}

/// Parse the site block's `bind` directives. Only network addresses the runtime can listen on are
/// accepted; unsupported networks or block options fail loudly instead of being dropped.
fn parse_site_bind(site: &SiteBlock) -> caddy_rs_core::Result<Vec<BindAddress>> {
    let mut binds = Vec::new();
    for directive in &site.directives {
        if directive.name != "bind" {
            continue;
        }
        if directive.args.is_empty() {
            return Err(adapter_error(
                directive.position,
                "directive `bind` requires at least one address",
            ));
        }
        if let Some(option) = directive.block.first() {
            return Err(adapter_error(
                option.position,
                format!(
                    "`bind` option `{}` is not supported by this build (listener protocols are \
                     not wired into the runtime yet; tracked as T-CONF-012)",
                    option.name
                ),
            ));
        }
        for raw in &directive.args {
            let (network, rest) = match raw.split_once('/') {
                Some((network, rest)) => (network.to_ascii_lowercase(), rest.to_string()),
                None => (String::new(), raw.clone()),
            };
            if !matches!(network.as_str(), "" | "tcp" | "tcp4" | "tcp6") {
                return Err(adapter_error(
                    directive.position,
                    format!(
                        "`bind` network `{network}` is not supported by this build \
                         (supported: tcp, tcp4, tcp6 and plain addresses)"
                    ),
                ));
            }
            // A bind address may include a port (Caddy ignores it in favour of the site key's
            // port); strip it so `[::1]:8080` and `[::1]` behave the same.
            let host = strip_bind_port(&rest);
            binds.push(BindAddress { network, host });
        }
    }
    Ok(binds)
}

/// Strip an optional port from a bind address host, keeping IPv6 brackets off.
fn strip_bind_port(address: &str) -> String {
    let address = address.trim();
    if let Some(rest) = address.strip_prefix('[') {
        // `[::1]` or `[::1]:8080`
        if let Some((host, _port)) = rest.split_once(']') {
            return host.to_string();
        }
    }
    // Bare IPv6 addresses contain multiple colons; a trailing `:port` is only meaningful for
    // hostnames/IPv4.
    if address.matches(':').count() == 1 {
        if let Some((host, port)) = address.rsplit_once(':') {
            if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                return host.to_string();
            }
        }
    }
    address.to_string()
}

/// Join a bind address with the listener port using Caddy's `JoinNetworkAddress` form.
fn join_bind_address(bind: &BindAddress, port: u16) -> caddy_rs_core::Result<String> {
    let host = bind.host.as_str();
    let address = if host.is_empty() {
        format!(":{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    if bind.network.is_empty() {
        Ok(address)
    } else {
        if host.contains('%') || host.contains('/') {
            return Err(caddy_rs_core::Error::invalid(
                "Caddyfile",
                format!("unsupported bind address `{}`", bind.host),
            ));
        }
        Ok(format!("{}/{}", bind.network, address))
    }
}

/// Extract the port from a listener address (`":443"`, `"127.0.0.1:443"`, `"tcp6/[::1]:443"`).
fn listen_port_of(listen: &str) -> Option<u16> {
    let (_, port) = listen.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

/// Parse the site block's `log` directives. Only the plain `log` form is implemented; options
/// must fail loudly until per-server logging is wired into the runtime (T-ADMIN-020).
fn parse_site_log(site: &SiteBlock) -> caddy_rs_core::Result<bool> {
    let mut has_log = false;
    for directive in &site.directives {
        if directive.name != "log" {
            continue;
        }
        if !directive.args.is_empty() || !directive.block.is_empty() {
            return Err(adapter_error(
                directive.position,
                "`log` options are not supported by this build (plain `log` only; tracked as \
                 T-ADMIN-020)",
            ));
        }
        has_log = true;
    }
    Ok(has_log)
}

/// Hostnames of a site block for access-log association: host only, with ports stripped, like
/// Caddy's `hostsFromKeys` + `net.SplitHostPort` sequence.
fn block_log_hosts(site: &SiteBlock, block: &SiteBlockPlan) -> (Vec<String>, bool) {
    let mut hosts = Vec::new();
    let mut catch_all = false;
    for address_index in &block.address_indices {
        let address = &site.addresses[*address_index];
        if address.host.is_empty() {
            catch_all = true;
            continue;
        }
        let host = address
            .host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if !hosts.iter().any(|existing| existing == &host) {
            hosts.push(host);
        }
    }
    (hosts, catch_all)
}

/// Server-level access-log association emitted by the plain `log` directive: logger names per host
/// plus the hosts that must be skipped because their site block does not enable logging.
fn build_server_logs(
    file: &parser::Caddyfile,
    server: &ServerBuilder,
    site_logs: &[bool],
) -> Option<Value> {
    if !server
        .blocks
        .iter()
        .any(|block| site_logs[block.site_index])
    {
        return None;
    }
    let mut logger_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut skip_hosts: Vec<String> = Vec::new();
    let mut skip_unmapped_hosts = false;
    for block in &server.blocks {
        let site = &file.sites[block.site_index];
        let (hosts, catch_all) = block_log_hosts(site, block);
        if site_logs[block.site_index] {
            for host in hosts {
                logger_names.entry(host).or_default().push(String::new());
            }
        } else if catch_all {
            skip_unmapped_hosts = true;
        } else {
            skip_hosts.extend(hosts);
        }
    }
    skip_hosts.sort();
    let mut logs = Map::new();
    if !logger_names.is_empty() {
        logs.insert("logger_names".to_string(), json!(logger_names));
    }
    if !skip_hosts.is_empty() {
        logs.insert("skip_hosts".to_string(), json!(skip_hosts));
    }
    if skip_unmapped_hosts {
        logs.insert("skip_unmapped_hosts".to_string(), json!(true));
    }
    Some(Value::Object(logs))
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

// ---------------------------------------------------------------------------
// TLS app generation (Caddy's httpcaddyfile/tlsapp.go for the supported subset)
// ---------------------------------------------------------------------------

/// Parsed `tls` directive of one site block.
#[derive(Clone, Debug, Default)]
struct SiteTls {
    /// `tls internal` or `tls <email>`.
    issuer: Option<TlsIssuer>,
    /// `tls <cert_file> <key_file>`.
    cert_key: Option<(String, String)>,
    /// `tls { on_demand }`.
    on_demand: bool,
    /// `tls { ca <endpoint> }`.
    ca: Option<String>,
    /// `tls { dns <provider> ... }`.
    dns: Option<parser::DnsProvider>,
    /// `tls { key_type <type> }`.
    key_type: Option<String>,
    /// `tls { issuer internal { ... } }` options (in addition to the `tls internal` shorthand).
    internal: Option<InternalIssuerOptions>,
    /// `tls { client_auth { ... } }` canonical `client_authentication` JSON.
    client_auth: Option<Value>,
    /// `tls { alpn <protocols...> }`.
    alpn: Option<Vec<String>>,
    /// `tls { protocols <min> [<max>] }`, translated to the runtime's `protocols` array.
    ///
    /// Caddy's adapted JSON spells this `protocol_min`/`protocol_max`, which the caddy-rs TLS
    /// terminator does not accept yet; emitting the array keeps the adapted config executable.
    /// Registered adapter divergence until the runtime grows min/max support (TLS-CONN-POLICY).
    protocols: Option<Vec<String>>,
}

/// Options of `tls { issuer internal { ... } }` (Caddy's `tls.issuance.internal`).
#[derive(Clone, Debug, Default)]
struct InternalIssuerOptions {
    /// Certificate authority ID (`ca`); defaults to `local`.
    ca: Option<String>,
    /// Certificate lifetime in nanoseconds (`lifetime`).
    lifetime_ns: Option<i64>,
    /// Sign with the root certificate directly (`sign_with_root`).
    sign_with_root: bool,
}

impl SiteTls {
    /// The internal-issuer options requested by this site, from either the `tls internal`
    /// shorthand or an explicit `issuer internal` block.
    fn internal_options(&self) -> Option<InternalIssuerOptions> {
        if let Some(internal) = &self.internal {
            return Some(internal.clone());
        }
        if matches!(self.issuer, Some(TlsIssuer::Internal)) {
            return Some(InternalIssuerOptions::default());
        }
        None
    }
}

#[derive(Clone, Debug)]
enum TlsIssuer {
    /// `tls internal`.
    Internal,
    /// `tls <email>`.
    Email(String),
}

/// One Caddy automation policy, in the subset this adapter builds.
#[derive(Clone, Debug, Default, PartialEq)]
struct AutomationPolicy {
    subjects: Vec<String>,
    issuers: Vec<Value>,
    on_demand: bool,
    key_type: Option<String>,
    reuse_private_keys: bool,
}

impl AutomationPolicy {
    fn encoded(&self) -> Value {
        let mut object = Map::new();
        if !self.subjects.is_empty() {
            object.insert("subjects".to_string(), json!(self.subjects));
        }
        if !self.issuers.is_empty() {
            object.insert("issuers".to_string(), Value::Array(self.issuers.clone()));
        }
        if self.on_demand {
            object.insert("on_demand".to_string(), json!(true));
        }
        if let Some(key_type) = &self.key_type {
            object.insert("key_type".to_string(), json!(key_type));
        }
        if self.reuse_private_keys {
            object.insert("reuse_private_keys".to_string(), json!(true));
        }
        Value::Object(object)
    }
}

/// Zerossl's ACME endpoint, Caddy's second default issuer when an email is configured.
const ZEROSSL_CA: &str = "https://acme.zerossl.com/v2/DV90";

/// The TLS-app plan for one adapted Caddyfile: the `apps.tls` value plus the TLS connection
/// policies each HTTP server needs.
struct TlsPlan {
    app: Option<Value>,
    connection_policies: Vec<Vec<Value>>,
}

#[derive(Default)]
struct ConnectionPolicyState {
    entries: Vec<Value>,
    has_catch_all: bool,
    address_qualifies: bool,
    auto_https_will_add: bool,
}

/// Encode the internal issuer module object (`tls.issuance.internal`).
fn internal_issuer_json(internal: &InternalIssuerOptions) -> Value {
    let mut object = Map::new();
    object.insert("module".to_string(), json!("internal"));
    if let Some(ca) = &internal.ca {
        object.insert("ca".to_string(), json!(ca));
    }
    if let Some(lifetime) = internal.lifetime_ns {
        object.insert("lifetime".to_string(), json!(lifetime));
    }
    if internal.sign_with_root {
        object.insert("sign_with_root".to_string(), json!(true));
    }
    Value::Object(object)
}

/// Encode the PKI app from the global `pki` option, or `None` when no CA was configured.
///
/// Caddy emits `apps.pki` only when the option defines at least one CA; `tls internal` without any
/// `pki` configuration relies on the default `local` CA provisioned implicitly by the PKI app.
fn pki_app_json(options: &parser::GlobalOptions) -> Option<Value> {
    let pki = options.pki.as_ref()?;
    if pki.certificate_authorities.is_empty() {
        return None;
    }
    let mut authorities = Map::new();
    for authority in &pki.certificate_authorities {
        let mut object = Map::new();
        if let Some(name) = &authority.name {
            object.insert("name".to_string(), json!(name));
        }
        if let Some(name) = &authority.root_common_name {
            object.insert("root_common_name".to_string(), json!(name));
        }
        if let Some(name) = &authority.intermediate_common_name {
            object.insert("intermediate_common_name".to_string(), json!(name));
        }
        if let Some(lifetime) = authority.intermediate_lifetime_ns {
            object.insert("intermediate_lifetime".to_string(), json!(lifetime));
        }
        if let Some(interval) = authority.maintenance_interval_ns {
            object.insert("maintenance_interval".to_string(), json!(interval));
        }
        if let Some(ratio) = authority.renewal_window_ratio {
            object.insert("renewal_window_ratio".to_string(), json!(ratio));
        }
        if let Some(root) = &authority.root {
            object.insert("root".to_string(), pki_key_pair_json(root));
        }
        if let Some(intermediate) = &authority.intermediate {
            object.insert("intermediate".to_string(), pki_key_pair_json(intermediate));
        }
        authorities.insert(authority.id.clone(), Value::Object(object));
    }
    Some(json!({"certificate_authorities": Value::Object(authorities)}))
}

fn pki_key_pair_json(pair: &parser::PkiKeyPairConfig) -> Value {
    let mut object = Map::new();
    if let Some(certificate) = &pair.certificate {
        object.insert("certificate".to_string(), json!(certificate));
    }
    if let Some(private_key) = &pair.private_key {
        object.insert("private_key".to_string(), json!(private_key));
    }
    if let Some(format) = &pair.format {
        object.insert("format".to_string(), json!(format));
    }
    Value::Object(object)
}

/// Parse the `tls` directive of a site block. Only the documented subset is implemented; other
/// forms fail loudly.
fn parse_site_tls(
    site: &SiteBlock,
    source: Option<&std::path::Path>,
) -> caddy_rs_core::Result<Option<SiteTls>> {
    let mut found: Option<&Directive> = None;
    for directive in &site.directives {
        if directive.name != "tls" {
            continue;
        }
        if found.is_some() {
            return Err(adapter_error(
                directive.position,
                "multiple `tls` directives in one site block are not supported by this build",
            ));
        }
        found = Some(directive);
    }
    let Some(directive) = found else {
        return Ok(None);
    };
    let position = directive.position;
    let mut config = SiteTls::default();
    match directive.args.as_slice() {
        [] => {}
        [single] if single == "internal" => config.issuer = Some(TlsIssuer::Internal),
        [single] if single == "force_automate" => {
            return Err(adapter_error(
                position,
                "`tls force_automate` is not supported by this build",
            ))
        }
        [single] if single.contains('@') => config.issuer = Some(TlsIssuer::Email(single.clone())),
        [cert, key] => config.cert_key = Some((cert.clone(), key.clone())),
        [_] => return Err(adapter_error(
            position,
            "single argument to `tls` must be 'internal', 'force_automate', or an email address",
        )),
        _ => {
            return Err(adapter_error(
                position,
                "`tls` takes at most two arguments (certificate and key files)",
            ))
        }
    }
    if directive.args.is_empty() && directive.block.is_empty() {
        return Err(adapter_error(
            position,
            "a naked `tls` directive is not allowed",
        ));
    }
    for option in &directive.block {
        match option.name.as_str() {
            "on_demand" => {
                if !option.args.is_empty() || !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`on_demand` does not take arguments",
                    ));
                }
                config.on_demand = true;
            }
            "ca" => {
                if option.args.len() != 1 || !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`ca` requires exactly one ACME CA endpoint",
                    ));
                }
                config.ca = Some(option.args[0].clone());
            }
            "dns" => {
                if !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`dns` does not support a block in this build",
                    ));
                }
                let Some(name) = option.args.first() else {
                    return Err(adapter_error(
                        option.position,
                        "`dns` requires a DNS provider name",
                    ));
                };
                config.dns = Some(parser::DnsProvider {
                    name: name.clone(),
                    args: option.args[1..].to_vec(),
                });
            }
            "key_type" => {
                if option.args.len() != 1 || !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`key_type` requires exactly one key type",
                    ));
                }
                config.key_type = Some(option.args[0].clone());
            }
            "issuer" => {
                if option.args.as_slice() != ["internal"] {
                    return Err(adapter_error(
                        option.position,
                        "`tls` option `issuer` only supports `internal`; ACME issuer \
                         configuration is not supported by this build",
                    ));
                }
                if config.issuer.is_some() {
                    return Err(adapter_error(
                        option.position,
                        "cannot specify both `tls internal` and a `tls { issuer ... }` block",
                    ));
                }
                let mut internal = InternalIssuerOptions::default();
                for sub in &option.block {
                    match sub.name.as_str() {
                        "ca" => {
                            if sub.args.len() != 1 || !sub.block.is_empty() {
                                return Err(adapter_error(
                                    sub.position,
                                    "`issuer internal ca` requires exactly one CA ID",
                                ));
                            }
                            if sub.args[0].trim().is_empty() {
                                return Err(adapter_error(
                                    sub.position,
                                    "`issuer internal ca` requires a non-empty CA ID",
                                ));
                            }
                            internal.ca = Some(sub.args[0].clone());
                        }
                        "lifetime" => {
                            if sub.args.len() != 1 || !sub.block.is_empty() {
                                return Err(adapter_error(
                                    sub.position,
                                    "`issuer internal lifetime` requires exactly one duration",
                                ));
                            }
                            let nanoseconds = crate::parser::parse_duration_ns(&sub.args[0])
                                .map_err(|reason| {
                                    adapter_error(
                                        sub.position,
                                        format!(
                                            "invalid `issuer internal lifetime` \
                                             `{}`: {reason}",
                                            sub.args[0]
                                        ),
                                    )
                                })?;
                            if nanoseconds <= 0 {
                                return Err(adapter_error(
                                    sub.position,
                                    "`issuer internal lifetime` must be positive",
                                ));
                            }
                            internal.lifetime_ns = Some(nanoseconds);
                        }
                        "sign_with_root" => {
                            if !sub.args.is_empty() || !sub.block.is_empty() {
                                return Err(adapter_error(
                                    sub.position,
                                    "`issuer internal sign_with_root` does not take arguments",
                                ));
                            }
                            internal.sign_with_root = true;
                        }
                        other => {
                            return Err(adapter_error(
                                sub.position,
                                format!(
                                "`issuer internal` option `{other}` is not supported by this build"
                            ),
                            ))
                        }
                    }
                }
                config.internal = Some(internal);
            }
            "client_auth" => {
                if config.client_auth.is_some() {
                    return Err(adapter_error(
                        option.position,
                        "duplicate tls option 'client_auth'",
                    ));
                }
                config.client_auth = Some(parse_client_auth_option(option, source)?);
            }
            "alpn" => {
                if config.alpn.is_some() {
                    return Err(adapter_error(
                        option.position,
                        "duplicate tls option 'alpn'",
                    ));
                }
                if option.args.is_empty() || !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`alpn` requires one or more protocol names",
                    ));
                }
                config.alpn = Some(option.args.clone());
            }
            "protocols" => {
                if config.protocols.is_some() {
                    return Err(adapter_error(
                        option.position,
                        "duplicate tls option 'protocols'",
                    ));
                }
                if !option.block.is_empty() {
                    return Err(adapter_error(
                        option.position,
                        "`protocols` does not take a block",
                    ));
                }
                const VERSIONS: [&str; 2] = ["tls1.2", "tls1.3"];
                let index_of = |version: &str| {
                    VERSIONS
                        .iter()
                        .position(|candidate| *candidate == version)
                        .ok_or_else(|| {
                            adapter_error(
                                option.position,
                                format!(
                                    "unsupported TLS protocol `{version}`; expected `tls1.2` or \
                                     `tls1.3`"
                                ),
                            )
                        })
                };
                let protocols: Vec<String> = match option.args.as_slice() {
                    [min] => {
                        let start = index_of(min)?;
                        VERSIONS[start..].iter().map(|v| v.to_string()).collect()
                    }
                    [min, max] => {
                        let start = index_of(min)?;
                        let end = index_of(max)?;
                        if start > end {
                            return Err(adapter_error(
                                option.position,
                                "`protocols` minimum version is newer than the maximum version",
                            ));
                        }
                        VERSIONS[start..=end]
                            .iter()
                            .map(|v| v.to_string())
                            .collect()
                    }
                    _ => {
                        return Err(adapter_error(
                            option.position,
                            "`protocols` takes one or two values (min [max])",
                        ))
                    }
                };
                config.protocols = Some(protocols);
            }
            "ciphers" => {
                return Err(adapter_error(
                    option.position,
                    "`tls` option `ciphers` is not supported by this build: the rustls terminator \
                     has no cipher-suite selection configuration (tracked as TLS-CIPHER-SUITES)",
                ))
            }
            "curves" => {
                return Err(adapter_error(
                    option.position,
                    "`tls` option `curves` is not supported by this build: the rustls terminator \
                     has no key-exchange-group selection configuration (tracked as TLS-CURVES)",
                ))
            }
            other => {
                return Err(adapter_error(
                    option.position,
                    format!("`tls` option `{other}` is not supported by this build"),
                ))
            }
        }
    }
    if config.client_auth.is_some()
        && site
            .addresses
            .iter()
            .any(|address| address.host.contains('*'))
    {
        return Err(adapter_error(
            position,
            "`client_auth` on wildcard hostnames requires Caddy's TLS shield-policy hoisting, \
             which is not supported by this build (tracked as TLS-CLIENT-AUTH); use explicit \
             hostnames",
        ));
    }
    if config.internal_options().is_some() && (config.ca.is_some() || config.dns.is_some()) {
        return Err(adapter_error(
            position,
            "cannot create both ACME and internal certificate issuers",
        ));
    }
    if config.cert_key.is_some() && (config.ca.is_some() || config.dns.is_some()) {
        return Err(adapter_error(
            position,
            "cannot mix a certificate/key pair with ACME issuer options",
        ));
    }
    Ok(Some(config))
}

/// Parse a `tls { client_auth { ... } }` block into Caddy's canonical
/// `client_authentication` JSON: `mode`, legacy `trusted_ca_cert`/`trusted_leaf_cert` fields
/// (file variants are read at adapt time, as Caddy does), and the `trust_pool inline|file`
/// modules. Unsupported providers/verifiers fail loudly.
fn parse_client_auth_option(
    option: &Directive,
    source: Option<&std::path::Path>,
) -> caddy_rs_core::Result<Value> {
    let base = source
        .and_then(std::path::Path::parent)
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut mode: Option<String> = None;
    let mut trusted_ca: Vec<String> = Vec::new();
    let mut trusted_leaf: Vec<String> = Vec::new();
    let mut ca_pool: Option<Value> = None;
    let mut saw_legacy_ca = false;
    for sub in &option.block {
        match sub.name.as_str() {
            "mode" => {
                if sub.args.len() != 1 || !sub.block.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "`client_auth` `mode` requires exactly one value",
                    ));
                }
                match sub.args[0].as_str() {
                    "request" | "require" | "verify_if_given" | "require_and_verify" => {
                        mode = Some(sub.args[0].clone());
                    }
                    other => {
                        return Err(adapter_error(
                            sub.position,
                            format!(
                                "unsupported client authentication mode `{other}`; expected \
                                 request, require, verify_if_given or require_and_verify"
                            ),
                        ))
                    }
                }
            }
            "trusted_ca_cert" => {
                if ca_pool.is_some() {
                    return Err(adapter_error(
                        sub.position,
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or \
                         'trusted_ca_cert_file'",
                    ));
                }
                if sub.args.len() != 1 || !sub.block.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "`trusted_ca_cert` requires exactly one base64 DER value",
                    ));
                }
                saw_legacy_ca = true;
                trusted_ca.push(sub.args[0].clone());
            }
            "trusted_ca_cert_file" => {
                if ca_pool.is_some() {
                    return Err(adapter_error(
                        sub.position,
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or \
                         'trusted_ca_cert_file'",
                    ));
                }
                if sub.args.len() != 1 || !sub.block.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "`trusted_ca_cert_file` requires exactly one PEM file",
                    ));
                }
                saw_legacy_ca = true;
                trusted_ca.extend(read_pem_certificates(
                    &base.join(&sub.args[0]),
                    sub.position,
                )?);
            }
            "trusted_leaf_cert" => {
                if sub.args.len() != 1 || !sub.block.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "`trusted_leaf_cert` requires exactly one base64 DER value",
                    ));
                }
                trusted_leaf.push(sub.args[0].clone());
            }
            "trusted_leaf_cert_file" => {
                if sub.args.len() != 1 || !sub.block.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "`trusted_leaf_cert_file` requires exactly one PEM file",
                    ));
                }
                trusted_leaf.extend(read_pem_certificates(
                    &base.join(&sub.args[0]),
                    sub.position,
                )?);
            }
            "trust_pool" => {
                if !trusted_ca.is_empty() {
                    return Err(adapter_error(
                        sub.position,
                        "cannot specify both 'trust_pool' and 'trusted_ca_cert' or \
                         'trusted_ca_cert_file'",
                    ));
                }
                if ca_pool.is_some() {
                    return Err(adapter_error(sub.position, "duplicate `trust_pool`"));
                }
                let Some(provider) = sub.args.first() else {
                    return Err(adapter_error(
                        sub.position,
                        "`trust_pool` requires a provider module",
                    ));
                };
                ca_pool = Some(match provider.as_str() {
                    "inline" => {
                        let mut certs = Vec::new();
                        for entry in &sub.block {
                            if entry.name != "trust_der" {
                                return Err(adapter_error(
                                    entry.position,
                                    format!(
                                        "`trust_pool inline` option `{}` is not supported by this \
                                         build",
                                        entry.name
                                    ),
                                ));
                            }
                            if entry.args.len() != 1 || !entry.block.is_empty() {
                                return Err(adapter_error(
                                    entry.position,
                                    "`trust_der` requires exactly one base64 DER value",
                                ));
                            }
                            certs.push(json!(entry.args[0]));
                        }
                        json!({"provider": "inline", "trusted_ca_certs": certs})
                    }
                    "file" => {
                        let mut files = Vec::new();
                        for entry in &sub.block {
                            if entry.name != "pem_file" {
                                return Err(adapter_error(
                                    entry.position,
                                    format!(
                                        "`trust_pool file` option `{}` is not supported by this \
                                         build",
                                        entry.name
                                    ),
                                ));
                            }
                            if entry.args.len() != 1 || !entry.block.is_empty() {
                                return Err(adapter_error(
                                    entry.position,
                                    "`pem_file` requires exactly one path",
                                ));
                            }
                            files.push(json!(entry.args[0]));
                        }
                        json!({"provider": "file", "pem_files": files})
                    }
                    other => {
                        return Err(adapter_error(
                            sub.position,
                            format!(
                                "client-auth trust pool provider `{other}` is not supported by \
                                 this build (runtime supports `inline` and `file`; tracked as \
                                 TLS-CLIENT-AUTH)"
                            ),
                        ))
                    }
                });
            }
            "verifier" => {
                return Err(adapter_error(
                    sub.position,
                    "custom client-auth verifiers (`verifier`) are not supported by this build \
                     (tracked as TLS-CLIENT-AUTH)",
                ))
            }
            other => {
                return Err(adapter_error(
                    sub.position,
                    format!("unknown subdirective for client_auth: {other}"),
                ))
            }
        }
    }
    let mut object = Map::new();
    if let Some(pool) = ca_pool {
        object.insert("ca".to_string(), pool);
    } else if saw_legacy_ca {
        object.insert(
            "ca".to_string(),
            json!({"provider": "inline", "trusted_ca_certs": trusted_ca}),
        );
    }
    if !trusted_leaf.is_empty() {
        object.insert("trusted_leaf_certs".to_string(), json!(trusted_leaf));
    }
    if let Some(mode) = mode {
        object.insert("mode".to_string(), json!(mode));
    }
    Ok(Value::Object(object))
}

/// Read a PEM file and return every `CERTIFICATE` block as base64 DER, matching Caddy's
/// `convertPEMFilesToDER` (which the deprecated `trusted_ca_cert_file`/`trusted_leaf_cert_file`
/// options use at adapt time).
fn read_pem_certificates(
    path: &std::path::Path,
    position: Position,
) -> caddy_rs_core::Result<Vec<String>> {
    let pem = std::fs::read_to_string(path).map_err(|error| {
        adapter_error(
            position,
            format!(
                "`trusted_ca_cert_file`/`trusted_leaf_cert_file` requires a readable PEM file at \
                 adapt time; reading `{}` failed: {error}",
                path.display()
            ),
        )
    })?;
    let mut certificates = Vec::new();
    let mut lines = pem.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "-----BEGIN CERTIFICATE-----" {
            continue;
        }
        let mut body = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            if line.trim() == "-----END CERTIFICATE-----" {
                closed = true;
                break;
            }
            body.push_str(line.trim());
        }
        if !closed {
            return Err(adapter_error(
                position,
                format!(
                    "PEM file `{}` has an unterminated certificate",
                    path.display()
                ),
            ));
        }
        let der = base64_decode(&body).ok_or_else(|| {
            adapter_error(
                position,
                format!("PEM file `{}` contains invalid base64", path.display()),
            )
        })?;
        certificates.push(base64_encode(&der));
    }
    if certificates.is_empty() {
        return Err(adapter_error(
            position,
            format!("PEM file `{}` contains no certificates", path.display()),
        ));
    }
    Ok(certificates)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut values = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        values.push(value as u32);
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        match chunk.len() {
            4 => {
                let triple = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
                out.push((triple >> 16) as u8);
                out.push((triple >> 8) as u8);
                out.push(triple as u8);
            }
            3 => {
                let triple = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6);
                out.push((triple >> 16) as u8);
                out.push((triple >> 8) as u8);
            }
            2 => {
                let triple = (chunk[0] << 18) | (chunk[1] << 12);
                out.push((triple >> 16) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `certmagic.DefaultIssuers`: the default ACME issuer, plus Zerossl when an email is set.
fn default_issuers(email: &str) -> Vec<Value> {
    let mut issuers = vec![json!({"module": "acme"})];
    if !email.trim().is_empty() {
        issuers.push(json!({
            "module": "acme",
            "ca": ZEROSSL_CA,
            "email": email,
        }));
    }
    issuers
}

/// Translate a DNS provider reference into Caddy's `dns.providers.<name>` module object.
fn dns_provider_json(
    provider: &parser::DnsProvider,
    position: Position,
) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    object.insert("name".to_string(), json!(provider.name));
    match provider.name.as_str() {
        // Caddy's test-only provider, kept so its upstream golden fixture can be matched.
        "mock" => {
            if provider.args.len() > 1 {
                return Err(adapter_error(
                    position,
                    "dns provider `mock` takes at most one argument",
                ));
            }
            if let Some(argument) = provider.args.first() {
                object.insert("argument".to_string(), json!(argument));
            }
        }
        "cloudflare" => {
            if provider.args.len() != 1 {
                return Err(adapter_error(
                    position,
                    "dns provider `cloudflare` requires an API token argument",
                ));
            }
            object.insert("api_token".to_string(), json!(provider.args[0]));
        }
        other => {
            return Err(adapter_error(
                position,
                format!(
                    "dns provider `{other}` is not supported by this build; supported providers: cloudflare"
                ),
            ))
        }
    }
    Ok(Value::Object(object))
}

/// Issuers Caddy creates for the implicit ACME shortcuts (`tls <email>`, `ca`, `dns`).
fn implicit_acme_issuers(tls: &SiteTls, position: Position) -> caddy_rs_core::Result<Vec<Value>> {
    let email = match &tls.issuer {
        Some(TlsIssuer::Email(email)) => Some(email.clone()),
        _ => None,
    };
    let mut bases: Vec<Map<String, Value>> = vec![Map::new()];
    if tls.ca.is_none() {
        if let Some(email) = &email {
            if !email.trim().is_empty() {
                let mut zerossl = Map::new();
                zerossl.insert("ca".to_string(), json!(ZEROSSL_CA));
                zerossl.insert("email".to_string(), json!(email));
                bases.push(zerossl);
            }
        }
    }
    let provider = match &tls.dns {
        Some(provider) => Some(dns_provider_json(provider, position)?),
        None => None,
    };
    let mut issuers = Vec::with_capacity(bases.len());
    for mut base in bases {
        base.insert("module".to_string(), json!("acme"));
        if let Some(email) = &email {
            base.entry("email".to_string())
                .or_insert_with(|| json!(email));
        }
        if let Some(ca) = &tls.ca {
            base.insert("ca".to_string(), json!(ca));
        }
        if let Some(provider) = &provider {
            base.insert(
                "challenges".to_string(),
                json!({"dns": {"provider": provider}}),
            );
        }
        issuers.push(Value::Object(base));
    }
    Ok(issuers)
}

/// `newBaseAutomationPolicy`: a policy populated from global options, or `None` when there are
/// no global automation options and `always` is false.
fn base_automation_policy(
    options: &parser::GlobalOptions,
    always: bool,
) -> Option<AutomationPolicy> {
    // Caddy's `newBaseAutomationPolicy` does NOT treat a bare global email as an automation
    // default; only `acme_ca`, `acme_ca_root` and `acme_dns` make the catch-all policy non-nil.
    let has_global_acme_defaults =
        options.acme_ca.is_some() || options.acme_ca_root.is_some() || options.acme_dns.is_some();
    if !options.local_certs && !has_global_acme_defaults {
        return always.then(AutomationPolicy::default);
    }
    let mut policy = AutomationPolicy::default();
    if options.local_certs {
        policy.issuers = vec![json!({"module": "internal"})];
    }
    Some(policy)
}

fn has_global_acme_defaults(options: &parser::GlobalOptions) -> bool {
    options.email.is_some()
        || options.acme_ca.is_some()
        || options.acme_ca_root.is_some()
        || options.acme_dns.is_some()
}

/// `fillInGlobalACMEDefaults` for an already-encoded issuer object.
fn fill_global_acme_defaults(issuer: &mut Value, options: &parser::GlobalOptions) {
    if issuer.get("module").and_then(Value::as_str) != Some("acme") {
        return;
    }
    let Some(object) = issuer.as_object_mut() else {
        return;
    };
    if let Some(email) = &options.email {
        object
            .entry("email".to_string())
            .or_insert_with(|| json!(email));
    }
    if let Some(ca) = &options.acme_ca {
        object.entry("ca".to_string()).or_insert_with(|| json!(ca));
    }
    if let Some(root) = &options.acme_ca_root {
        let roots = object
            .entry("trusted_roots_pem_files".to_string())
            .or_insert_with(|| json!([]));
        if let Some(roots) = roots.as_array_mut() {
            if !roots.iter().any(|value| value.as_str() == Some(root)) {
                roots.push(json!(root));
            }
        }
    }
    if let Some(global_dns) = &options.acme_dns {
        let challenges = object
            .entry("challenges".to_string())
            .or_insert_with(|| json!({}));
        if let Some(challenges) = challenges.as_object_mut() {
            let dns = challenges
                .entry("dns".to_string())
                .or_insert_with(|| json!({}));
            if let Some(dns) = dns.as_object_mut() {
                if dns.get("provider").is_none() {
                    if let Ok(provider) =
                        dns_provider_json(global_dns, Position { line: 0, column: 0 })
                    {
                        dns.insert("provider".to_string(), provider);
                    }
                }
            }
        }
    }
}

/// Caddy's host specificity for a block: hosts from its keys (empty when a key has no host).
fn hosts_from_keys(addresses: &[&parser::SiteAddress]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for address in addresses {
        if address.host.is_empty() {
            return Vec::new();
        }
        let host = address
            .host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// `hostsFromKeysNotHTTP`: hosts that are served with certificates.
fn hosts_not_http(addresses: &[&parser::SiteAddress], http_port: u16) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for address in addresses {
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
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

fn subject_is_internal(subject: &str) -> bool {
    subject == "localhost"
        || subject.ends_with(".localhost")
        || subject.ends_with(".local")
        || subject.ends_with(".internal")
        || subject.ends_with(".home.arpa")
        || subject.parse::<std::net::IpAddr>().is_ok()
}

/// `certmagic.SubjectQualifiesForPublicCert` (with Caddy's on-demand wildcard allowance).
fn subject_qualifies_for_public_cert(policy: &AutomationPolicy, subject: &str) -> bool {
    if subject.is_empty() || subject_is_internal(subject) {
        return false;
    }
    subject.matches("*.").count() < 2 || policy.on_demand
}

fn automation_policy_has_all_public_names(policy: &AutomationPolicy) -> bool {
    policy
        .subjects
        .iter()
        .all(|subject| subject_qualifies_for_public_cert(policy, subject))
}

/// Glob matching with `*` matching any run of characters, as `certmagic.MatchWildcard` does for
/// configured subject patterns (a wildcard covers any number of labels).
fn wildcard_matches(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    fn matches(name: &[u8], pattern: &[u8]) -> bool {
        match pattern.first() {
            None => name.is_empty(),
            Some(b'*') => {
                if matches(name, &pattern[1..]) {
                    return true;
                }
                !name.is_empty() && matches(&name[1..], pattern)
            }
            Some(expected) => name.first() == Some(expected) && matches(&name[1..], &pattern[1..]),
        }
    }
    matches(name.as_bytes(), pattern.as_bytes())
}

/// `automationPolicyIsSubset`: every subject of `policy` is covered by `other`.
fn automation_policy_is_subset(policy: &AutomationPolicy, other: &AutomationPolicy) -> bool {
    if other.subjects.is_empty() {
        return true;
    }
    if policy.subjects.is_empty() {
        return false;
    }
    policy.subjects.iter().all(|subject| {
        other
            .subjects
            .iter()
            .any(|candidate| wildcard_matches(subject, candidate))
    })
}

fn automation_policy_shadows(index: usize, policies: &[AutomationPolicy]) -> Option<usize> {
    (index + 1..policies.len())
        .find(|candidate| automation_policy_is_subset(&policies[index], &policies[*candidate]))
}

fn automation_policy_implicit_class(policy: &AutomationPolicy) -> &'static str {
    if policy.subjects.is_empty() {
        return "catch-all";
    }
    let mut has_public = false;
    let mut has_internal = false;
    for subject in &policy.subjects {
        if subject_qualifies_for_public_cert(policy, subject) {
            has_public = true;
        } else {
            has_internal = true;
        }
    }
    match (has_public, has_internal) {
        (true, true) => "mixed",
        (true, false) => "public",
        _ => "internal",
    }
}

fn automation_policy_uses_default_internal_issuer(policy: &AutomationPolicy) -> bool {
    if policy.issuers.is_empty() {
        return automation_policy_implicit_class(policy) == "internal";
    }
    policy.issuers == vec![json!({"module": "internal"})]
}

fn automation_policies_have_same_issuers(
    left: &AutomationPolicy,
    right: &AutomationPolicy,
) -> bool {
    if left.issuers == right.issuers {
        if !left.issuers.is_empty() {
            return true;
        }
        let left_class = automation_policy_implicit_class(left);
        let right_class = automation_policy_implicit_class(right);
        return left_class == "catch-all"
            || right_class == "catch-all"
            || left_class == right_class;
    }
    automation_policy_uses_default_internal_issuer(left)
        && automation_policy_uses_default_internal_issuer(right)
}

fn automation_policy_is_empty(policy: &AutomationPolicy) -> bool {
    policy.issuers.is_empty()
        && !policy.on_demand
        && policy.key_type.is_none()
        && !policy.reuse_private_keys
}

fn automation_policies_can_combine(left: &AutomationPolicy, right: &AutomationPolicy) -> bool {
    automation_policies_have_same_issuers(left, right)
        && left.on_demand == right.on_demand
        && left.key_type == right.key_type
        && left.reuse_private_keys == right.reuse_private_keys
}

/// Caddy's `consolidateAutomationPolicies`: sort most-specific first, drop redundant empty
/// policies, then merge policies that are identical apart from their subjects.
fn consolidate_automation_policies(mut policies: Vec<AutomationPolicy>) -> Vec<AutomationPolicy> {
    policies.sort_by(|left, right| {
        let left_before = if automation_policy_is_subset(left, right) {
            true
        } else if automation_policy_is_subset(right, left) {
            false
        } else {
            left.subjects.len() > right.subjects.len()
        };
        let right_before = if automation_policy_is_subset(right, left) {
            true
        } else if automation_policy_is_subset(left, right) {
            false
        } else {
            right.subjects.len() > left.subjects.len()
        };
        if left_before {
            std::cmp::Ordering::Less
        } else if right_before {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });

    let original_len = policies.len();
    let mut empty_count = 0usize;
    let mut index = 0usize;
    while index < policies.len() {
        if automation_policy_is_empty(&policies[index]) {
            empty_count += 1;
            let shadow = automation_policy_shadows(index, &policies);
            let mut empty_policy = AutomationPolicy::default();
            empty_policy.subjects = policies[index].subjects.clone();
            if let Some(shadow) = shadow {
                empty_policy.subjects = policies[shadow].subjects.clone();
            }
            if index == policies.len() - 1
                || shadow.is_some_and(|shadow| policies[shadow] == empty_policy)
            {
                policies.remove(index);
                continue;
            }
        }
        index += 1;
    }
    if empty_count == original_len {
        return Vec::new();
    }

    let mut index: isize = 0;
    'outer: while (index as usize) < policies.len() {
        let mut inner = (index + 1) as usize;
        while inner < policies.len() {
            if policies[index as usize] == policies[inner] {
                policies.remove(inner);
                continue 'outer;
            }
            if automation_policies_can_combine(&policies[index as usize], &policies[inner]) {
                if !policies[index as usize].subjects.is_empty()
                    && policies[inner].subjects.is_empty()
                {
                    if automation_policy_shadows(index as usize, &policies)
                        .is_some_and(|shadow| shadow >= inner)
                    {
                        policies.remove(index as usize);
                        continue 'outer;
                    }
                } else {
                    for subject in policies[inner].subjects.clone() {
                        if !policies[index as usize].subjects.contains(&subject) {
                            policies[index as usize].subjects.push(subject);
                        }
                    }
                    policies.remove(inner);
                    continue;
                }
            }
            inner += 1;
        }
        index += 1;
    }
    policies
}

/// A simplified `consolidateConnPolicies`: connection policies in this subset differ only by
/// their matchers and certificate-selection tags.
fn consolidate_connection_policies(mut policies: Vec<Value>) -> Vec<Value> {
    // Catch-all policies (no matcher) must come last, as Caddy sorts them.
    policies.sort_by_key(|policy| usize::from(policy.get("match").is_none()));
    loop {
        let mut removed = false;
        let mut left = 0;
        while left < policies.len() {
            let mut right = left + 1;
            while right < policies.len() {
                if policies[left] == policies[right] {
                    policies.remove(right);
                    removed = true;
                    continue;
                }
                if policies[left].get("match") == policies[right].get("match") {
                    let tags = policies[right]
                        .get("certificate_selection")
                        .and_then(|selection| selection.get("any_tag"))
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(selection) = policies[left]
                        .pointer_mut("/certificate_selection/any_tag")
                        .and_then(Value::as_array_mut)
                    {
                        for tag in tags {
                            if !selection.contains(&tag) {
                                selection.push(tag);
                            }
                        }
                    }
                    policies.remove(right);
                    removed = true;
                    continue;
                }
                right += 1;
            }
            left += 1;
        }
        if !removed {
            return policies;
        }
    }
}

/// Build `apps.tls` and the per-server TLS connection policies from the parsed Caddyfile,
/// mirroring Caddy's `buildTLSApp`/`serversFromPairings` for the supported subset.
fn build_tls_plan(
    file: &parser::Caddyfile,
    site_tls: &[Option<SiteTls>],
    servers: &[ServerBuilder],
    http_port: u16,
    https_port: u16,
) -> caddy_rs_core::Result<TlsPlan> {
    let options = &file.options;
    let auto_https_off = options.auto_https.off;

    // Hosts that share a server block with a hostless key are not route-matcher hosts, so Caddy
    // adds them to `certificates.automate` explicitly.
    let mut shared_hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if !auto_https_off {
        for server in servers {
            for block in &server.blocks {
                let site = &file.sites[block.site_index];
                let has_hostless = block
                    .address_indices
                    .iter()
                    .any(|index| site.addresses[*index].host.is_empty());
                if !has_hostless {
                    continue;
                }
                for index in &block.address_indices {
                    let address = &site.addresses[*index];
                    if address.host.is_empty()
                        || address.scheme.as_deref() == Some("http")
                        || address.port == Some(http_port)
                    {
                        continue;
                    }
                    let host = address.host.trim_start_matches('[').trim_end_matches(']');
                    shared_hosts.insert(host.to_string());
                }
            }
        }
    }

    let mut policies: Vec<AutomationPolicy> = Vec::new();
    let mut catch_all_base = base_automation_policy(options, false);
    if let Some(base) = &catch_all_base {
        policies.push(base.clone());
    }
    let mut load_files: Vec<Value> = Vec::new();
    let mut cert_tags: BTreeMap<String, String> = BTreeMap::new();
    let mut connection_states: Vec<ConnectionPolicyState> = servers
        .iter()
        .map(|_| ConnectionPolicyState {
            auto_https_will_add: !auto_https_off,
            ..ConnectionPolicyState::default()
        })
        .collect();

    for (server_index, server) in servers.iter().enumerate() {
        let listen_port = server
            .listens
            .first()
            .and_then(|listen| listen_port_of(listen));
        if listen_port == Some(http_port) {
            continue;
        }
        for block in &server.blocks {
            let site = &file.sites[block.site_index];
            let addresses: Vec<&parser::SiteAddress> = block
                .address_indices
                .iter()
                .map(|index| &site.addresses[*index])
                .collect();
            if addresses
                .iter()
                .all(|address| address.scheme.as_deref() == Some("http"))
            {
                continue;
            }
            let tls = site_tls[block.site_index].clone();
            let hosts = hosts_from_keys(&addresses);
            let mut policy =
                base_automation_policy(options, true).expect("always returns a policy");
            if hosts.is_empty() {
                if let Some(base) = &catch_all_base {
                    policy = base.clone();
                }
            }
            if let Some(tls) = &tls {
                policy.on_demand |= tls.on_demand;
                if tls.key_type.is_some() {
                    policy.key_type = tls.key_type.clone();
                }
                if tls.cert_key.is_none() {
                    if let Some(internal) = tls.internal_options() {
                        policy.issuers = vec![internal_issuer_json(&internal)];
                    } else if tls.issuer.is_some() || tls.ca.is_some() || tls.dns.is_some() {
                        policy.issuers = implicit_acme_issuers(tls, site.position)?;
                    }
                }
            }
            if hosts.is_empty() && catch_all_base.is_none() {
                catch_all_base = Some(policy.clone());
            }
            let mut subjects = hosts_not_http(&addresses, http_port);
            subjects.sort();
            policy.subjects = subjects;

            if policy.issuers.is_empty() {
                let mut external = Vec::new();
                let mut internal = Vec::new();
                for subject in &policy.subjects {
                    if subject_qualifies_for_public_cert(&policy, subject) {
                        external.push(subject.clone());
                    } else {
                        internal.push(subject.clone());
                    }
                }
                if !external.is_empty() && !internal.is_empty() {
                    policy.subjects = external;
                    let mut internal_policy = policy.clone();
                    internal_policy.subjects = internal;
                    internal_policy.issuers = vec![json!({"module": "internal"})];
                    policies.push(internal_policy);
                }
            }
            policies.push(policy);

            // Connection policies contributed by this block's `tls` directive.
            let state = &mut connection_states[server_index];
            if let Some(tls) = &tls {
                let mut connection_policy = Map::new();
                if !hosts.is_empty() {
                    let mut sni = hosts.clone();
                    sni.sort();
                    connection_policy.insert("match".to_string(), json!({"sni": sni}));
                }
                if let Some((cert, key)) = &tls.cert_key {
                    let tag = match cert_tags.get(cert) {
                        Some(tag) => tag.clone(),
                        None => {
                            let tag = format!("cert{}", cert_tags.len());
                            cert_tags.insert(cert.clone(), tag.clone());
                            load_files.push(json!({
                                "certificate": cert,
                                "key": key,
                                "tags": [tag],
                            }));
                            tag
                        }
                    };
                    connection_policy.insert(
                        "certificate_selection".to_string(),
                        json!({"any_tag": [tag]}),
                    );
                }
                if let Some(client_auth) = &tls.client_auth {
                    connection_policy
                        .insert("client_authentication".to_string(), client_auth.clone());
                }
                if let Some(alpn) = &tls.alpn {
                    connection_policy.insert("alpn".to_string(), json!(alpn));
                }
                if let Some(protocols) = &tls.protocols {
                    connection_policy.insert("protocols".to_string(), json!(protocols));
                }
                let has_listener_options =
                    tls.client_auth.is_some() || tls.alpn.is_some() || tls.protocols.is_some();
                if connection_policy.contains_key("certificate_selection") || has_listener_options {
                    if hosts.is_empty() {
                        state.has_catch_all = true;
                    }
                    state.entries.push(Value::Object(connection_policy));
                }
            }

            // Auto-HTTPS bookkeeping for this server.
            for address in &addresses {
                let explicit_port = address.port;
                let host = address.host.trim_start_matches('[').trim_end_matches(']');
                let has_tls_enabled = tls.is_some()
                    || (!address.host.is_empty()
                        && !server.skip_auto_https.iter().any(|skip| skip == host));
                if address.scheme.as_deref() == Some("https")
                    || (address.scheme.as_deref() != Some("http")
                        && explicit_port != Some(http_port)
                        && has_tls_enabled)
                {
                    state.address_qualifies = true;
                }
                state.auto_https_will_add = state.auto_https_will_add
                    && (explicit_port == Some(https_port)
                        || (explicit_port != Some(http_port) && !address.host.is_empty()));
            }
        }
    }

    // Automate loader: hosts shared with a hostless key always need explicit management.
    let mut automate: Vec<String> = shared_hosts.iter().cloned().collect();
    automate.sort();
    let mut internal_subjects: Vec<String> = shared_hosts
        .iter()
        .filter(|host| !subject_qualifies_for_public_cert(&AutomationPolicy::default(), host))
        .cloned()
        .collect();
    internal_subjects.sort();
    if !internal_subjects.is_empty() {
        policies.push(AutomationPolicy {
            subjects: internal_subjects,
            issuers: vec![json!({"module": "internal"})],
            ..AutomationPolicy::default()
        });
    }

    // Global ACME defaults apply to every policy that has no issuers and only public names.
    if has_global_acme_defaults(options) {
        for policy in &mut policies {
            if policy.issuers.is_empty() && automation_policy_has_all_public_names(policy) {
                policy.issuers = default_issuers(options.email.as_deref().unwrap_or(""));
                if options.acme_ca.is_some() {
                    policy.issuers = vec![json!({"module": "acme"})];
                }
            }
        }
    }
    for policy in &mut policies {
        for issuer in &mut policy.issuers {
            fill_global_acme_defaults(issuer, options);
        }
    }

    let policies = consolidate_automation_policies(policies);
    let mut seen_subjects: BTreeSet<&str> = BTreeSet::new();
    for policy in &policies {
        for subject in &policy.subjects {
            if !seen_subjects.insert(subject.as_str()) {
                return Err(adapter_error(
                    Position { line: 0, column: 0 },
                    format!(
                        "hostname appears in more than one automation policy, making certificate \
                         management ambiguous: {subject}"
                    ),
                ));
            }
        }
    }

    let mut tls_object = Map::new();
    if !policies.is_empty() {
        let encoded: Vec<Value> = policies.iter().map(AutomationPolicy::encoded).collect();
        tls_object.insert("automation".to_string(), json!({"policies": encoded}));
    }
    if !automate.is_empty() || !load_files.is_empty() {
        let mut certificates = Map::new();
        if !automate.is_empty() {
            certificates.insert("automate".to_string(), json!(automate));
        }
        if !load_files.is_empty() {
            certificates.insert("load_files".to_string(), Value::Array(load_files));
        }
        tls_object.insert("certificates".to_string(), Value::Object(certificates));
    }

    let mut connection_policies = Vec::with_capacity(servers.len());
    for (index, state) in connection_states.into_iter().enumerate() {
        let mut entries = state.entries;
        if state.address_qualifies
            && !state.has_catch_all
            && (!entries.is_empty() || !state.auto_https_will_add)
        {
            entries.push(json!({}));
        }
        let _ = index;
        connection_policies.push(consolidate_connection_policies(entries));
    }

    Ok(TlsPlan {
        app: (!tls_object.is_empty()).then_some(Value::Object(tls_object)),
        connection_policies,
    })
}

/// `try_files` is not a handler directive: Caddy expands it to a file matcher plus a rewrite of
/// the matched relative path. Arguments with a query string become separate grouped routes.
fn build_try_files_routes(directive: &Directive) -> caddy_rs_core::Result<Vec<Value>> {
    if directive.args.is_empty() {
        return Err(adapter_error(
            directive.position,
            "directive `try_files` requires at least one file argument",
        ));
    }
    let mut policy: Option<String> = None;
    for option in &directive.block {
        match option.name.as_str() {
            "policy" => {
                if policy.is_some() {
                    return Err(adapter_error(
                        option.position,
                        "try policy already configured",
                    ));
                }
                let Some(value) = option.args.first() else {
                    return Err(adapter_error(
                        option.position,
                        "`policy` requires an argument",
                    ));
                };
                if !matches!(
                    value.as_str(),
                    "first_exist"
                        | "first_exist_fallback"
                        | "largest_size"
                        | "smallest_size"
                        | "most_recently_modified"
                ) {
                    return Err(adapter_error(
                        option.position,
                        format!("unrecognized try policy: {value}"),
                    ));
                }
                policy = Some(value.clone());
            }
            other => {
                return Err(adapter_error(
                    option.position,
                    format!("`try_files` option `{other}` is not supported"),
                ));
            }
        }
    }
    let make_route = |try_files: &[String], query: &str| -> Value {
        let mut file_matcher = Map::new();
        file_matcher.insert("try_files".to_string(), json!(try_files));
        if let Some(policy) = &policy {
            file_matcher.insert("try_policy".to_string(), json!(policy));
        }
        let route = json!({
            "match": [{"file": Value::Object(file_matcher)}],
            "handle": [{"handler": "rewrite", "uri": format!("{{http.matchers.file.relative}}{query}")}],
        });
        route
    };
    let mut routes: Vec<Value> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    for item in &directive.args {
        let item = &qualify_placeholders(item);
        if let Some(index) = item.find('?') {
            if !pending.is_empty() {
                routes.push(make_route(&pending, ""));
                pending.clear();
            }
            routes.push(make_route(&[item[..index].to_string()], &item[index..]));
        } else {
            pending.push(item.clone());
        }
    }
    if !pending.is_empty() {
        routes.push(make_route(&pending, ""));
    }
    // Caddy groups these routes so only the first matching rewrite runs.
    if routes.len() > 1 {
        for route in &mut routes {
            route["group"] = json!("group1");
        }
    }
    Ok(routes)
}

/// `uri strip_prefix` maps directly onto the rewrite handler's `strip_path_prefix`, which the
/// runtime implements; the other `uri` operations have no runtime support yet and fail loudly.
fn uri_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    let Some(operation) = args.first() else {
        return Err(adapter_error(
            position,
            "directive `uri` requires an operation (strip_prefix)",
        ));
    };
    match operation.as_str() {
        "strip_prefix" => {
            if args.len() != 2 {
                return Err(adapter_error(
                    position,
                    "`uri strip_prefix` requires exactly one argument",
                ));
            }
            Ok(json!({
                "handler": "rewrite",
                "strip_path_prefix": qualify_placeholders(&args[1]),
            }))
        }
        other => Err(adapter_error(
            position,
            format!(
                "`uri {other}` is not supported by this build (only `strip_prefix` has a \
                 runtime implementation; tracked as T-CONF-027)"
            ),
        )),
    }
}

fn build_site_routes(
    site: &SiteBlock,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Vec<Value>> {
    let matchers = collect_matchers(&site.directives)?;
    build_routes(&site.directives, &matchers, true, true, warnings)
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
        if let Some(regexp) = object.get_mut("vars_regexp").and_then(Value::as_object_mut) {
            for value in regexp.values_mut() {
                if let Some(value) = value.as_object_mut() {
                    value
                        .entry("name".to_string())
                        .or_insert_with(|| json!(name));
                }
            }
        }
        if let Some(expression) = object.get_mut("expression").and_then(Value::as_object_mut) {
            expression
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
    const KNOWN_MATCHERS: &[&str] = &[
        "host",
        "path",
        "method",
        "header",
        "path_regexp",
        "query",
        "not",
        "remote_ip",
        "client_ip",
        "vars",
        "vars_regexp",
    ];
    if args.len() == 1 && !KNOWN_MATCHERS.contains(&name.as_str()) {
        // Caddy treats a lone quoted argument that is not a known matcher name as an inline
        // CEL expression matcher (`path('/foo*') && method('GET')`).
        return Ok(json!({"expression": {"expr": name}}));
    }
    matcher_from_directive(name, &args[1..], position)
}

fn matcher_from_directives(directives: &[Directive]) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    for directive in directives {
        if directive.name == "not" {
            let inner = if directive.block.is_empty() {
                matcher_from_inline_args(&directive.args, directive.position)?
            } else {
                matcher_from_directives(&directive.block)?
            };
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
            if let Some(field) = field.strip_prefix('!') {
                if field.is_empty() {
                    return Err(adapter_error(
                        position,
                        "malformed header matcher: must have field name following ! character",
                    ));
                }
                if args.len() > 1 {
                    return Err(adapter_error(
                        position,
                        "malformed header matcher: null matching headers cannot have a field value",
                    ));
                }
                let mut header = Map::new();
                header.insert(field.to_string(), Value::Null);
                return Ok(json!({"header": Value::Object(header)}));
            }
            let Some(value) = args.get(1) else {
                return Err(adapter_error(
                    position,
                    "malformed header matcher: expected both field and value",
                ));
            };
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
            if args.is_empty() {
                return Err(adapter_error(
                    position,
                    "matcher `query` requires at least one key=value pair",
                ));
            }
            let mut query: Map<String, Value> = Map::new();
            for pair in args {
                let Some((key, value)) = pair.split_once('=') else {
                    return Err(adapter_error(
                        position,
                        format!(
                            "malformed query matcher token: {pair}; must be in param=val format"
                        ),
                    ));
                };
                match query.get_mut(key) {
                    Some(Value::Array(values)) => values.push(json!(value)),
                    _ => {
                        query.insert(key.to_string(), json!([value]));
                    }
                }
            }
            Ok(json!({"query": Value::Object(query)}))
        }
        "vars" => {
            if args.len() < 2 {
                return Err(adapter_error(
                    position,
                    "matcher `vars` requires a name and a value",
                ));
            }
            Ok(json!({"vars": {args[0].clone(): [args[1].clone()]}}))
        }
        "vars_regexp" => {
            let (regexp_name, field, pattern) = match args {
                [field, pattern] => (None, field, pattern),
                [name, field, pattern, ..] => (Some(name.clone()), field, pattern),
                _ => {
                    return Err(adapter_error(
                        position,
                        "matcher `vars_regexp` requires [name] field and pattern",
                    ))
                }
            };
            let mut value = Map::new();
            value.insert("pattern".to_string(), json!(pattern));
            if let Some(name) = regexp_name {
                value.insert("name".to_string(), json!(name));
            }
            Ok(json!({"vars_regexp": {field.clone(): Value::Object(value)}}))
        }
        "not" => {
            // Inline form: `not <matcher> [args...]`.
            if args.is_empty() {
                return Err(adapter_error(position, "matcher `not` requires a matcher"));
            }
            let inner = matcher_from_directive(&args[0], &args[1..], position)?;
            Ok(json!({"not": [inner]}))
        }
        "remote_ip" | "client_ip" => {
            if args.is_empty() {
                return Err(adapter_error(
                    position,
                    format!("matcher `{name}` requires at least one range"),
                ));
            }
            let mut ranges = Vec::new();
            for range in args {
                if range == "private_ranges" {
                    for private in [
                        "192.168.0.0/16",
                        "172.16.0.0/12",
                        "10.0.0.0/8",
                        "127.0.0.1/8",
                        "fd00::/8",
                        "::1",
                    ] {
                        ranges.push(json!(private));
                    }
                } else {
                    ranges.push(json!(range));
                }
            }
            Ok(json!({ name: {"ranges": ranges} }))
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
    top_level: bool,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Vec<Value>> {
    let mut ordered: Vec<&Directive> = Vec::new();
    for directive in directives {
        if directive.name.starts_with('@') {
            continue;
        }
        if directive.name == "tls" {
            if top_level {
                // Handled by the TLS app builder, not as an HTTP handler.
                continue;
            }
            return Err(adapter_error(
                directive.position,
                "directive `tls` can only be used directly in a site block",
            ));
        }
        if directive.name == "bind" || directive.name == "log" {
            if top_level {
                // Handled at the server/listener level, not as an HTTP handler.
                continue;
            }
            return Err(adapter_error(
                directive.position,
                format!(
                    "directive `{}` can only be used directly in a site block",
                    directive.name
                ),
            ));
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
                let mut route_args = directive.args.clone();
                let matcher = matcher_for_args(&mut route_args, matchers, directive.position)?;
                if !route_args.is_empty() {
                    return Err(adapter_error(
                        directive.position,
                        "unexpected arguments to `route` (only an optional matcher is accepted)",
                    ));
                }
                // Matchers defined inside the block are scoped to it (Caddy segment scope).
                let mut inner_matchers = matchers.clone();
                inner_matchers.extend(collect_matchers(&directive.block)?);
                let inner =
                    build_routes(&directive.block, &inner_matchers, false, false, warnings)?;
                let subroute = if inner.is_empty() {
                    json!({"handler": "subroute"})
                } else {
                    json!({"handler": "subroute", "routes": inner})
                };
                let mut route = Map::new();
                route.insert("handle".to_string(), json!([subroute]));
                if let Some(matcher) = matcher {
                    route.insert("match".to_string(), json!([matcher]));
                }
                entries.push((name, Value::Object(route)));
            }
            "handle" | "handle_path" => {
                let mut route = build_handle_route(directive, matchers, warnings)?;
                if handle_count > 1 {
                    route["group"] = json!("group1");
                }
                entries.push((name, route));
            }
            "try_files" => {
                for route in build_try_files_routes(directive)? {
                    entries.push((name, route));
                }
            }
            _ => {
                let mut args = directive.args.clone();
                // `root` is ambiguous: a single argument is always the root path, never a path
                // matcher (Caddy's parseRoot uses the argument count to disambiguate).
                let matcher = if name == "root" && args.len() == 1 {
                    None
                } else {
                    matcher_for_args(&mut args, matchers, directive.position)?
                };
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
        // Caddy's `sortRoutes` special-cases `vars`: it reverses the (most-specific-first) order
        // so the least-specific matcher runs first and the last matching `vars` wins. Since
        // several `vars` routes share one directive slot they form one contiguous run.
        let mut start = 0;
        while start < entries.len() {
            if entries[start].0 != "vars" {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < entries.len() && entries[end].0 == "vars" {
                end += 1;
            }
            entries[start..end].reverse();
            start = end;
        }
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
    let mut inner_matchers = matchers.clone();
    inner_matchers.extend(collect_matchers(&directive.block)?);
    inner.extend(build_routes(
        &directive.block,
        &inner_matchers,
        true,
        false,
        warnings,
    )?);

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

/// Caddy's `request_body` directive: emit the canonical `request_body` handler with `max_size`
/// (humanize.ParseBytes units, decimal by default) and the experimental `set` body replacement.
fn request_body_handler(directive: &Directive) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("request_body"));
    for option in &directive.block {
        match option.name.as_str() {
            "max_size" => {
                if option.args.len() != 1 {
                    return Err(adapter_error(
                        option.position,
                        "wrong argument count or unexpected line ending after `max_size`",
                    ));
                }
                let size = parse_caddy_size(&option.args[0]).map_err(|error| {
                    adapter_error(option.position, format!("parsing max_size: {error}"))
                })?;
                if size > i64::MAX as u64 {
                    return Err(adapter_error(
                        option.position,
                        format!("parsing max_size: size {size} is out of range"),
                    ));
                }
                // Caddy's RequestBody uses `omitempty`, and its ServeHTTP applies the limit only
                // when MaxSize > 0.
                if size > 0 {
                    object.insert("max_size".to_string(), json!(size));
                }
            }
            "set" => {
                if option.args.len() != 1 {
                    return Err(adapter_error(
                        option.position,
                        "wrong argument count or unexpected line ending after `set`",
                    ));
                }
                let value = qualify_placeholders(&option.args[0]);
                if !value.is_empty() {
                    object.insert("set".to_string(), json!(value));
                }
            }
            other => {
                return Err(adapter_error(
                    option.position,
                    format!("unrecognized request_body subdirective '{other}'"),
                ));
            }
        }
    }
    Ok(Value::Object(object))
}

/// Parse a size the way Caddy does (`go-humanize.ParseBytes`): an optional fractional number
/// (commas allowed as thousand separators) followed by an optional size suffix. Decimal suffixes
/// (`kb`, `mb`, …) use powers of 1000; `kib`/`mib`/… use powers of 1024; the bare `k`/`m`/`g`/…
/// forms are also accepted. Results are truncated to whole bytes.
fn parse_caddy_size(value: &str) -> Result<u64, String> {
    let text = value.trim();
    let mut end = 0;
    for (index, character) in text.char_indices() {
        if character.is_ascii_digit() || character == '.' || character == ',' {
            end = index + character.len_utf8();
        } else {
            break;
        }
    }
    let number_text = text[..end].replace(',', "");
    let suffix = text[end..].trim().to_ascii_lowercase();
    let number: f64 = number_text
        .parse()
        .map_err(|_| format!("strconv.ParseFloat: parsing \"{number_text}\": invalid syntax"))?;
    let multiplier: u64 = match suffix.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1_024,
        "m" | "mb" => 1_000_000,
        "mib" => 1_048_576,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1_073_741_824,
        "t" | "tb" => 1_000_000_000_000,
        "tib" => 1_099_511_627_776,
        "p" | "pb" => 1_000_000_000_000_000,
        "pib" => 1_125_899_906_842_624,
        "e" | "eb" => 1_000_000_000_000_000_000,
        "eib" => 1_152_921_504_606_846_976,
        other => return Err(format!("unhandled size name: {other}")),
    };
    if !number.is_finite() || number < 0.0 {
        return Err(format!(
            "strconv.ParseFloat: parsing \"{number_text}\": invalid syntax"
        ));
    }
    let product = number * multiplier as f64;
    if product >= u64::MAX as f64 {
        return Err(format!("size {value} is out of range"));
    }
    Ok(product as u64)
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
        "uri" => vec![uri_handler(args, directive.position)?],
        "header" => header_handlers(directive, args)?,
        "request_body" => vec![request_body_handler(directive)?],
        "encode" => vec![encode_handler(directive)?],
        "reverse_proxy" => vec![reverse_proxy_handler(directive, args)?],
        "basicauth" | "basic_auth" => vec![basic_auth_handler(directive, args)?],
        "forward_auth" => vec![forward_auth_handler(directive, args)?],
        "invoke" => vec![invoke_handler(args, directive.position)?],
        "vars" => vec![vars_handler(directive, args)?],
        "map" => vec![map_handler(directive, args)?],
        other => {
            return Err(adapter_error(
                directive.position,
                format!("directive `{other}` is not implemented by the adapter"),
            ))
        }
    };
    Ok(handlers)
}

/// Caddy's `basic_auth` directive: emit the canonical `authentication` handler with the
/// HTTP Basic provider (`providers.http_basic`).
fn basic_auth_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    let mut hash_name = "bcrypt".to_string();
    let mut realm: Option<String> = None;
    match args {
        [] => {}
        [hash] => hash_name = hash.clone(),
        [hash, configured_realm] => {
            hash_name = hash.clone();
            realm = Some(configured_realm.clone());
        }
        _ => {
            return Err(adapter_error(
                directive.position,
                "`basic_auth` takes at most a hash algorithm and a realm",
            ))
        }
    }
    if hash_name != "bcrypt" && hash_name != "argon2id" {
        return Err(adapter_error(
            directive.position,
            format!("unrecognized hash algorithm: {hash_name}"),
        ));
    }

    let mut accounts = Vec::new();
    for account in &directive.block {
        if !account.block.is_empty() || account.args.len() != 1 {
            return Err(adapter_error(
                account.position,
                "username and password cannot be empty or missing",
            ));
        }
        let username = account.name.as_str();
        let password = account.args[0].as_str();
        if username.is_empty() || password.is_empty() {
            return Err(adapter_error(
                account.position,
                "username and password cannot be empty or missing",
            ));
        }
        accounts.push(json!({"username": username, "password": password}));
    }

    let mut provider = Map::new();
    provider.insert("hash".to_string(), json!({"algorithm": hash_name}));
    if !accounts.is_empty() {
        provider.insert("accounts".to_string(), Value::Array(accounts));
    }
    if let Some(realm) = realm {
        provider.insert("realm".to_string(), json!(realm));
    }
    Ok(json!({
        "handler": "authentication",
        "providers": {"http_basic": Value::Object(provider)},
    }))
}

/// Caddy's `forward_auth` directive: adapt to Caddy's canonical expansion, a `reverse_proxy`
/// handler that rewrites the request to the auth service, forwards the original method/URI, and
/// copies configured response headers back onto the request on a 2xx response.
fn forward_auth_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    let mut uri: Option<String> = None;
    let mut headers_to_copy: BTreeMap<String, String> = BTreeMap::new();
    let mut trusted_proxies: Vec<Value> = Vec::new();
    let mut passthrough: Vec<Directive> = Vec::new();
    for item in &directive.block {
        match item.name.as_str() {
            "uri" => {
                if item.args.len() != 1 || !item.block.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`forward_auth` option `uri` requires exactly one argument",
                    ));
                }
                if uri.is_some() {
                    return Err(adapter_error(
                        item.position,
                        format!("cannot re-declare uri: {}", item.args[0]),
                    ));
                }
                uri = Some(item.args[0].clone());
            }
            "copy_headers" => {
                let mut fields = item.args.clone();
                for nested in &item.block {
                    if !nested.args.is_empty() || !nested.block.is_empty() {
                        return Err(adapter_error(
                            nested.position,
                            "unexpected arguments in a `copy_headers` block",
                        ));
                    }
                    fields.push(nested.name.clone());
                }
                if fields.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`copy_headers` requires at least one header field",
                    ));
                }
                for field in fields {
                    match field.split_once('>') {
                        Some((from, to)) => {
                            headers_to_copy.insert(from.to_string(), to.to_string());
                        }
                        None => {
                            headers_to_copy.insert(field.clone(), field);
                        }
                    }
                }
            }
            "trusted_proxies" => {
                for argument in &item.args {
                    if argument == "private_ranges" {
                        return Err(adapter_error(
                            item.position,
                            "`trusted_proxies private_ranges` is not supported by this build",
                        ));
                    }
                    trusted_proxies.push(json!(argument));
                }
            }
            _ => passthrough.push(item.clone()),
        }
    }
    let Some(uri) = uri else {
        return Err(adapter_error(
            directive.position,
            "the 'uri' subdirective is required",
        ));
    };

    // The rest of the block uses reverse_proxy syntax.
    let synthetic = Directive {
        name: "reverse_proxy".to_string(),
        args: Vec::new(),
        arg_quoted: Vec::new(),
        block: passthrough,
        position: directive.position,
    };
    let base = reverse_proxy_handler(&synthetic, args)?;
    let mut object = base.as_object().cloned().unwrap_or_default();
    object.insert("rewrite".to_string(), json!({"method": "GET", "uri": uri}));
    if !trusted_proxies.is_empty() {
        object.insert("trusted_proxies".to_string(), Value::Array(trusted_proxies));
    }

    // Preserve the original method and URI for the auth service before the rewrite.
    let headers = object
        .entry("headers".to_string())
        .or_insert_with(|| json!({}));
    if let Some(headers) = headers.as_object_mut() {
        let request = headers
            .entry("request".to_string())
            .or_insert_with(|| json!({}));
        if let Some(request) = request.as_object_mut() {
            let set = request
                .entry("set".to_string())
                .or_insert_with(|| json!({}));
            if let Some(set) = set.as_object_mut() {
                set.entry("X-Forwarded-Method".to_string())
                    .or_insert_with(|| json!(["{http.request.method}"]));
                set.entry("X-Forwarded-Uri".to_string())
                    .or_insert_with(|| json!(["{http.request.uri}"]));
            }
        }
    }

    // On a 2xx auth response, copy the configured headers back onto the original request. The
    // delete-then-conditional-set pattern prevents a client from injecting a header the auth
    // service did not return.
    let mut copy_routes: Vec<Value> = vec![json!({"handle": [{"handler": "vars"}]})];
    for (from, to) in &headers_to_copy {
        let to = canonical_header_key(to);
        let placeholder = format!(
            "{{http.reverse_proxy.header.{}}}",
            canonical_header_key(from)
        );
        copy_routes.push(json!({
            "handle": [{"handler": "headers", "request": {"delete": [to]}}],
        }));
        let mut set = Map::new();
        set.insert(to.clone(), json!([placeholder.clone()]));
        let mut vars = Map::new();
        vars.insert(placeholder, json!([""]));
        copy_routes.push(json!({
            "handle": [{
                "handler": "headers",
                "request": {"set": Value::Object(set)},
            }],
            "match": [{"not": [{"vars": Value::Object(vars)}]}],
        }));
    }
    object.insert(
        "handle_response".to_string(),
        json!([{"match": {"status_code": [2]}, "routes": copy_routes}]),
    );
    Ok(Value::Object(object))
}

/// `http.CanonicalHeaderKey`: capitalize the first letter and letters after `-`, lowercase the
/// rest; return the value unchanged when it is not a valid header token.
fn canonical_header_key(value: &str) -> String {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return value.to_string();
    }
    let mut canonical = String::with_capacity(value.len());
    let mut uppercase_next = true;
    for character in value.chars() {
        if uppercase_next {
            canonical.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            canonical.extend(character.to_lowercase());
        }
        if character == '-' {
            uppercase_next = true;
        }
    }
    canonical
}

/// Caddy's `invoke` directive: a handler that runs a named route attached to the server.
fn invoke_handler(args: &[String], position: Position) -> caddy_rs_core::Result<Value> {
    match args {
        [name] => Ok(json!({"handler": "invoke", "name": name})),
        _ => Err(adapter_error(
            position,
            "`invoke` requires exactly one named-route name",
        )),
    }
}

/// Caddy's `vars` directive: set request variables, with Caddy's scalar conversion of unquoted
/// values (numbers, booleans, otherwise strings).
fn vars_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("vars"));
    if !args.is_empty() {
        let [name, value] = args else {
            return Err(adapter_error(
                directive.position,
                "`vars` requires a name and a value",
            ));
        };
        object.insert(name.clone(), scalar_json(value));
    }
    for item in &directive.block {
        if !item.block.is_empty() || item.args.len() != 1 {
            return Err(adapter_error(
                item.position,
                "`vars` block entries require a name and a value",
            ));
        }
        object.insert(item.name.clone(), scalar_json(&item.args[0]));
    }
    Ok(Value::Object(object))
}

/// `caddyfile.Dispenser.ScalarVal` for a token whose quotedness is no longer tracked.
fn scalar_json(text: &str) -> Value {
    if let Ok(value) = text.parse::<i64>() {
        return json!(value);
    }
    if let Ok(value) = text.parse::<f64>() {
        return json!(value);
    }
    if text == "true" {
        return json!(true);
    }
    if text == "false" {
        return json!(false);
    }
    json!(text)
}

/// Caddy's `http.handlers.map` handler: map the placeholder in `source` through the block's
/// mappings into one or more destination placeholders. Exact inputs are compared literally, inputs
/// prefixed with `~` are regular expressions (with `${N}` capture references in the outputs),
/// `default` supplies fallbacks, and outputs are Caddy scalars (quoted tokens stay strings; an
/// unquoted `-` becomes null).
fn map_handler(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Value> {
    let Some(source) = args.first() else {
        return Err(adapter_error(
            directive.position,
            "directive `map` requires a source argument",
        ));
    };
    let destinations: Vec<String> = args[1..].to_vec();
    if destinations.is_empty() {
        return Err(adapter_error(
            directive.position,
            "missing destination argument(s)",
        ));
    }
    for destination in &destinations {
        let qualified = qualify_placeholders(destination);
        if qualified != *destination {
            return Err(adapter_error(
                directive.position,
                format!(
                    "destination {destination} conflicts with a Caddyfile placeholder shorthand"
                ),
            ));
        }
    }
    let mut mappings: Vec<Value> = Vec::new();
    let mut defaults: Option<Vec<Value>> = None;
    for item in &directive.block {
        if item.name == "default" {
            if defaults.is_some() {
                return Err(adapter_error(item.position, "defaults already defined"));
            }
            let mut values: Vec<Value> = item
                .args
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    scalar_json_quoted(value, item.arg_quoted.get(index).copied().unwrap_or(false))
                })
                .collect();
            while values.len() < destinations.len() {
                values.push(json!(""));
            }
            defaults = Some(values);
            continue;
        }
        let input = qualify_placeholders(&item.name);
        let mut outputs: Vec<Value> = item
            .args
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let text = qualify_placeholders(value);
                scalar_json_quoted(&text, item.arg_quoted.get(index).copied().unwrap_or(false))
            })
            .collect();
        if outputs.len() > destinations.len() {
            return Err(adapter_error(item.position, "too many outputs"));
        }
        while outputs.len() < destinations.len() {
            outputs.push(Value::Null);
        }
        let mapping = if let Some(regexp) = input.strip_prefix('~') {
            json!({"input_regexp": regexp, "outputs": outputs})
        } else {
            json!({"input": input, "outputs": outputs})
        };
        mappings.push(mapping);
    }
    let mut object = Map::new();
    object.insert("handler".to_string(), json!("map"));
    object.insert("source".to_string(), json!(qualify_placeholders(source)));
    object.insert("destinations".to_string(), json!(destinations));
    if !mappings.is_empty() {
        object.insert("mappings".to_string(), Value::Array(mappings));
    }
    if let Some(defaults) = defaults {
        object.insert("defaults".to_string(), Value::Array(defaults));
    }
    Ok(Value::Object(object))
}

/// `caddyfile.Dispenser.ScalarVal`: quoted tokens are always strings; unquoted tokens are parsed
/// as integers, floats, or booleans where possible. `-` is null in Caddy's map outputs (handled by
/// the caller via [`scalar_json_quoted`] before scalar conversion).
fn scalar_json_quoted(text: &str, quoted: bool) -> Value {
    if text == "-" {
        return Value::Null;
    }
    if quoted {
        return json!(text);
    }
    scalar_json(text)
}

/// Names invoked by a directive list, recursively.
fn collect_invoke_names(directives: &[Directive], out: &mut Vec<String>) {
    for directive in directives {
        if directive.name == "invoke" {
            if let Some(name) = directive.args.first() {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
        }
        collect_invoke_names(&directive.block, out);
    }
}

/// Build the JSON route for a `&(name) { ... }` definition, following Caddy's
/// `extractNamedRoutes` simplification for a single matcher-less route.
fn build_named_route(
    named: &parser::NamedRoute,
    warnings: &mut Vec<String>,
) -> caddy_rs_core::Result<Value> {
    let matchers = collect_matchers(&named.directives)?;
    let routes = build_routes(&named.directives, &matchers, true, true, warnings)?;
    if routes.len() == 1 && routes[0].get("match").is_none() {
        // Caddy keeps only the first handler of a single matcher-less route here.
        let first_handler = routes[0]
            .get("handle")
            .and_then(Value::as_array)
            .and_then(|handlers| handlers.first())
            .cloned()
            .unwrap_or_else(|| json!({"handler": "subroute"}));
        Ok(json!({"handle": [first_handler]}))
    } else {
        Ok(json!({"handle": [{"handler": "subroute", "routes": routes}]}))
    }
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

/// Canonicalise a header field name the way Go's `textproto.CanonicalMIMEHeaderKey` does:
/// upper-case the first letter and every letter after a hyphen, lower-case the rest.
fn canonical_header_name(field: &str) -> String {
    let mut output = String::with_capacity(field.len());
    let mut upper = true;
    for ch in field.chars() {
        if ch == '-' {
            output.push('-');
            upper = true;
        } else if upper {
            output.extend(ch.to_uppercase());
            upper = false;
        } else {
            output.extend(ch.to_lowercase());
        }
    }
    output
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

/// Response-header operations being accumulated from one `header` directive.
#[derive(Default)]
struct HeaderOpsPlan {
    add: BTreeMap<String, Vec<String>>,
    set: BTreeMap<String, Vec<String>>,
    delete: Vec<String>,
    replace: BTreeMap<String, Vec<(String, String)>>,
    require: Option<Map<String, Value>>,
    deferred: bool,
}

impl HeaderOpsPlan {
    fn is_empty(&self) -> bool {
        self.add.is_empty()
            && self.set.is_empty()
            && self.delete.is_empty()
            && self.replace.is_empty()
            && self.require.is_none()
    }

    /// Caddy's `applyHeaderOp`.
    fn apply(&mut self, field: &str, value: &str, replacement: Option<&str>) {
        let field = field.trim_end_matches(':');
        if let Some(name) = field.strip_prefix('+') {
            self.add
                .entry(canonical_header_name(name))
                .or_default()
                .push(qualify_placeholders(value));
        } else if let Some(name) = field.strip_prefix('-') {
            self.delete.push(canonical_header_name(name));
            self.deferred = true;
        } else if let Some(name) = field.strip_prefix('?') {
            let require = self.require.get_or_insert_with(Map::new);
            let headers = require
                .entry("headers".to_string())
                .or_insert_with(|| json!({}));
            if let Some(headers) = headers.as_object_mut() {
                headers.insert(canonical_header_name(name), Value::Null);
            }
            self.set.insert(
                canonical_header_name(name),
                vec![qualify_placeholders(value)],
            );
        } else if let Some(replacement) = replacement {
            if field.starts_with('>') {
                self.deferred = true;
            }
            let name = field.trim_start_matches(['+', '-', '?', '>']);
            self.replace
                .entry(canonical_header_name(name))
                .or_default()
                .push((
                    qualify_placeholders(value),
                    qualify_placeholders(replacement),
                ));
        } else if let Some(name) = field.strip_prefix('>') {
            self.set.insert(
                canonical_header_name(name),
                vec![qualify_placeholders(value)],
            );
            self.deferred = true;
        } else {
            self.set.insert(
                canonical_header_name(field),
                vec![qualify_placeholders(value)],
            );
        }
    }

    fn response(&self) -> Map<String, Value> {
        let mut response = Map::new();
        if !self.add.is_empty() {
            response.insert("add".to_string(), json!(self.add));
        }
        if !self.set.is_empty() {
            response.insert("set".to_string(), json!(self.set));
        }
        if !self.delete.is_empty() {
            response.insert("delete".to_string(), json!(self.delete));
        }
        if !self.replace.is_empty() {
            let replace: Map<String, Value> = self
                .replace
                .iter()
                .map(|(field, replacements)| {
                    let replacements: Vec<Value> = replacements
                        .iter()
                        .map(|(search, replacement)| {
                            json!({"search_regexp": search, "replace": replacement})
                        })
                        .collect();
                    (field.clone(), Value::Array(replacements))
                })
                .collect();
            response.insert("replace".to_string(), Value::Object(replace));
        }
        if let Some(require) = &self.require {
            response.insert("require".to_string(), Value::Object(require.clone()));
        }
        if self.deferred {
            response.insert("deferred".to_string(), json!(true));
        }
        response
    }

    fn encode(&self) -> Option<Value> {
        if self.is_empty() {
            return None;
        }
        Some(json!({"handler": "headers", "response": self.response()}))
    }
}

fn header_handlers(directive: &Directive, args: &[String]) -> caddy_rs_core::Result<Vec<Value>> {
    // Caddy builds two handlers: one for ordinary operations and one for `?` (conditional set)
    // operations, because those need a response matcher.
    let mut handler = HeaderOpsPlan::default();
    let mut require_handler = HeaderOpsPlan::default();

    let has_inline = !args.is_empty();
    if has_inline {
        if args.len() > 3 {
            return Err(adapter_error(
                directive.position,
                "`header` takes at most a field, value and replacement",
            ));
        }
        handler.apply(
            &args[0],
            args.get(1).map(String::as_str).unwrap_or(""),
            args.get(2).map(String::as_str),
        );
    }

    for item in &directive.block {
        match item.name.as_str() {
            "defer" => {
                if !item.args.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`header` option `defer` does not take arguments",
                    ));
                }
                if has_inline {
                    return Err(adapter_error(
                        item.position,
                        "cannot specify headers in both arguments and block",
                    ));
                }
                handler.deferred = true;
            }
            "match" => {
                if has_inline {
                    return Err(adapter_error(
                        item.position,
                        "cannot specify headers in both arguments and block",
                    ));
                }
                let matcher = response_matcher(item)?;
                let require = handler.require.get_or_insert_with(Map::new);
                merge_response_matcher(require, matcher);
            }
            _ => {
                if has_inline {
                    return Err(adapter_error(
                        item.position,
                        "cannot specify headers in both arguments and block",
                    ));
                }
                let field = item.name.as_str();
                let target = if field.starts_with('?') {
                    &mut require_handler
                } else {
                    &mut handler
                };
                target.apply(
                    field,
                    item.args.first().map(String::as_str).unwrap_or(""),
                    item.args.get(1).map(String::as_str),
                );
            }
        }
    }

    let mut handlers = Vec::new();
    if let Some(handler) = handler.encode() {
        handlers.push(handler);
    }
    if let Some(handler) = require_handler.encode() {
        handlers.push(handler);
    }
    Ok(handlers)
}

/// Parse Caddy's response matcher used by `header { match ... }`.
fn response_matcher(item: &Directive) -> caddy_rs_core::Result<Map<String, Value>> {
    let mut matcher = Map::new();
    if item.block.is_empty() {
        if item.args.is_empty() {
            return Err(adapter_error(
                item.position,
                "`match` requires a response matcher",
            ));
        }
        add_response_matcher_part(&mut matcher, &item.args[0], &item.args[1..], item.position)?;
    } else {
        for part in &item.block {
            add_response_matcher_part(&mut matcher, &part.name, &part.args, part.position)?;
        }
    }
    Ok(matcher)
}

fn add_response_matcher_part(
    matcher: &mut Map<String, Value>,
    name: &str,
    args: &[String],
    position: Position,
) -> caddy_rs_core::Result<()> {
    match name {
        "status" => {
            if args.is_empty() {
                return Err(adapter_error(position, "`match status` requires a code"));
            }
            let mut codes = Vec::new();
            for code in args {
                codes.push(
                    parse_status_range(code).map_err(|message| adapter_error(position, message))?,
                );
            }
            let entry = matcher
                .entry("status_code".to_string())
                .or_insert_with(|| json!([]));
            if let Some(entry) = entry.as_array_mut() {
                entry.extend(codes.into_iter().map(|code| json!(code)));
            }
        }
        "header" => {
            let Some(field) = args.first() else {
                return Err(adapter_error(
                    position,
                    "`match header` requires a field name",
                ));
            };
            let values: Vec<Value> = args.iter().skip(1).map(|value| json!(value)).collect();
            let headers = matcher
                .entry("headers".to_string())
                .or_insert_with(|| json!({}));
            if let Some(headers) = headers.as_object_mut() {
                headers.insert(field.clone(), Value::Array(values));
            }
        }
        other => {
            return Err(adapter_error(
                position,
                format!("response matcher `{other}` is not supported by this build"),
            ))
        }
    }
    Ok(())
}

fn merge_response_matcher(target: &mut Map<String, Value>, source: Map<String, Value>) {
    for (key, value) in source {
        match target.get_mut(&key) {
            Some(Value::Array(existing)) => {
                if let Value::Array(incoming) = value {
                    existing.extend(incoming);
                }
            }
            Some(Value::Object(existing)) => {
                if let Value::Object(incoming) = value {
                    for (field, value) in incoming {
                        existing.insert(field, value);
                    }
                }
            }
            _ => {
                target.insert(key, value);
            }
        }
    }
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
                // Caddy's status is a WeakString: numeric codes are emitted as numbers, anything
                // else (e.g. placeholders such as `{env.CUSTOM_STATUS}`) as a string.
                let value = match status.parse::<u16>() {
                    Ok(code) => json!(code),
                    Err(_) => json!(status),
                };
                object.insert("status_code".to_string(), value);
            }
            "disable_canonical_uris" => {
                object.insert("canonical_uris".to_string(), json!(false));
            }
            "precompressed" => {
                // Caddy defaults an empty format list to br, zstd, gzip and emits a module map
                // plus the preference order.
                let formats: Vec<String> = if values.is_empty() {
                    ["br", "zstd", "gzip"]
                        .iter()
                        .map(|format| (*format).to_string())
                        .collect()
                } else {
                    values.to_vec()
                };
                let mut precompressed = Map::new();
                for format in &formats {
                    if !matches!(format.as_str(), "br" | "zstd" | "gzip") {
                        return Err(adapter_error(
                            directive.position,
                            format!(
                                "`file_server precompressed` format `{format}` is not supported \
                                 by this build; expected br, zstd or gzip"
                            ),
                        ));
                    }
                    precompressed.insert(format.clone(), json!({}));
                }
                object.insert("precompressed".to_string(), Value::Object(precompressed));
                object.insert("precompressed_order".to_string(), json!(formats));
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
        if let Some(dynamic) = directive.block.iter().find(|item| item.name == "dynamic") {
            return Err(adapter_error(
                dynamic.position,
                "`reverse_proxy` dynamic upstreams are not supported by this build \
                 (tracked as T-PROXY-036); use static upstreams",
            ));
        }
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
        let parsed = parse_upstreams(target).map_err(|message| {
            adapter_error(
                directive.position,
                format!("upstream `{target}`: {message}"),
            )
        })?;
        for parsed in parsed {
            https_target |= parsed.https;
            h2c_target |= parsed.h2c;
            upstreams.push(json!({"dial": qualify_placeholders(&parsed.dial)}));
        }
    }

    let mut object = Map::new();
    object.insert("handler".to_string(), json!("reverse_proxy"));
    object.insert("upstreams".to_string(), Value::Array(upstreams));

    let mut load_balancing = Map::new();
    let mut request_headers = Map::new();
    let mut response_headers = Map::new();
    let mut retry_match: Vec<Value> = Vec::new();
    let mut health_active: Option<Map<String, Value>> = None;
    let mut health_passive: Option<Map<String, Value>> = None;

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
            "health_uri" => {
                let uri = single_argument(item, "health_uri")?;
                health_active_map(&mut health_active).insert("uri".to_string(), json!(uri));
            }
            "health_headers" => {
                if !item.args.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`health_headers` does not take inline arguments",
                    ));
                }
                // Caddy accumulates repeated fields into one list and keeps a header written
                // without values as a single empty string.
                let mut headers = Map::new();
                for header in &item.block {
                    // This build's lexer tokenises a bare `{...}` at the start of a value as a
                    // block; a block cannot be a health-header value in Caddy's Caddyfile, so
                    // report it instead of silently dropping the placeholder.
                    if !header.block.is_empty() {
                        return Err(adapter_error(
                            header.position,
                            "unquoted `{...}` placeholder in a `health_headers` value is not \
                             supported by this build; quote the value",
                        ));
                    }
                    let mut values: Vec<Value> =
                        header.args.iter().map(|value| json!(value)).collect();
                    if values.is_empty() {
                        values.push(json!(""));
                    }
                    match headers.get_mut(&header.name) {
                        Some(Value::Array(existing)) => existing.extend(values),
                        _ => {
                            headers.insert(header.name.clone(), Value::Array(values));
                        }
                    }
                }
                let active = health_active_map(&mut health_active);
                if !headers.is_empty() {
                    active.insert("headers".to_string(), Value::Object(headers));
                }
            }
            "health_method" => {
                let method = single_argument(item, "health_method")?;
                health_active_map(&mut health_active).insert("method".to_string(), json!(method));
            }
            "health_request_body" => {
                let body = single_argument(item, "health_request_body")?;
                health_active_map(&mut health_active).insert("body".to_string(), json!(body));
            }
            "health_interval" => {
                let value = single_argument(item, "health_interval")?;
                let nanos = parse_duration(value)
                    .map_err(|message| adapter_error(item.position, message))?;
                health_active_map(&mut health_active).insert("interval".to_string(), json!(nanos));
            }
            "health_timeout" => {
                let value = single_argument(item, "health_timeout")?;
                let nanos = parse_duration(value)
                    .map_err(|message| adapter_error(item.position, message))?;
                health_active_map(&mut health_active).insert("timeout".to_string(), json!(nanos));
            }
            "health_status" => {
                let value = single_argument(item, "health_status")?;
                let status = parse_health_status(value)
                    .map_err(|message| adapter_error(item.position, message))?;
                health_active_map(&mut health_active)
                    .insert("expect_status".to_string(), json!(status));
            }
            "health_body" => {
                let body = single_argument(item, "health_body")?;
                health_active_map(&mut health_active)
                    .insert("expect_body".to_string(), json!(body));
            }
            "health_follow_redirects" => {
                if !item.args.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`health_follow_redirects` does not take arguments",
                    ));
                }
                health_active_map(&mut health_active)
                    .insert("follow_redirects".to_string(), json!(true));
            }
            "health_passes" => {
                let value = single_argument(item, "health_passes")?;
                let passes =
                    parse_count(value).map_err(|message| adapter_error(item.position, message))?;
                health_active_map(&mut health_active).insert("passes".to_string(), json!(passes));
            }
            "health_fails" => {
                let value = single_argument(item, "health_fails")?;
                let fails =
                    parse_count(value).map_err(|message| adapter_error(item.position, message))?;
                health_active_map(&mut health_active).insert("fails".to_string(), json!(fails));
            }
            "max_fails" => {
                let value = single_argument(item, "max_fails")?;
                let max_fails =
                    parse_count(value).map_err(|message| adapter_error(item.position, message))?;
                health_passive_map(&mut health_passive)
                    .insert("max_fails".to_string(), json!(max_fails));
            }
            "fail_duration" => {
                let value = single_argument(item, "fail_duration")?;
                let nanos = parse_duration(value)
                    .map_err(|message| adapter_error(item.position, message))?;
                health_passive_map(&mut health_passive)
                    .insert("fail_duration".to_string(), json!(nanos));
            }
            "unhealthy_request_count" => {
                let value = single_argument(item, "unhealthy_request_count")?;
                let count =
                    parse_count(value).map_err(|message| adapter_error(item.position, message))?;
                health_passive_map(&mut health_passive)
                    .insert("unhealthy_request_count".to_string(), json!(count));
            }
            "unhealthy_latency" => {
                let value = single_argument(item, "unhealthy_latency")?;
                let nanos = parse_duration(value)
                    .map_err(|message| adapter_error(item.position, message))?;
                health_passive_map(&mut health_passive)
                    .insert("unhealthy_latency".to_string(), json!(nanos));
            }
            "unhealthy_status" => {
                if item.args.is_empty() {
                    return Err(adapter_error(
                        item.position,
                        "`unhealthy_status` requires at least one status code",
                    ));
                }
                let mut statuses = Vec::new();
                for value in &item.args {
                    statuses.push(
                        parse_health_status(value)
                            .map_err(|message| adapter_error(item.position, message))?,
                    );
                }
                let passive = health_passive_map(&mut health_passive);
                match passive.get_mut("unhealthy_status") {
                    Some(Value::Array(existing)) => {
                        existing.extend(statuses.into_iter().map(|status| json!(status)));
                    }
                    _ => {
                        passive.insert("unhealthy_status".to_string(), json!(statuses));
                    }
                }
            }
            "header_up" => {
                if item.args.len() < 2 {
                    return Err(adapter_error(
                        item.position,
                        "`header_up` requires a field and value",
                    ));
                }
                request_headers.insert(
                    canonical_header_name(&item.args[0]),
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
                    canonical_header_name(&item.args[0]),
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
    if health_active.is_some() || health_passive.is_some() {
        let mut health_checks = Map::new();
        if let Some(active) = health_active {
            health_checks.insert("active".to_string(), Value::Object(active));
        }
        if let Some(passive) = health_passive {
            health_checks.insert("passive".to_string(), Value::Object(passive));
        }
        object.insert("health_checks".to_string(), Value::Object(health_checks));
    }
    Ok(Value::Object(object))
}

fn health_active_map(slot: &mut Option<Map<String, Value>>) -> &mut Map<String, Value> {
    slot.get_or_insert_with(Map::new)
}

fn health_passive_map(slot: &mut Option<Map<String, Value>>) -> &mut Map<String, Value> {
    slot.get_or_insert_with(Map::new)
}

fn single_argument<'a>(directive: &'a Directive, option: &str) -> caddy_rs_core::Result<&'a str> {
    match directive.args.as_slice() {
        [value] => Ok(value),
        _ => Err(adapter_error(
            directive.position,
            format!("`{option}` requires exactly one value"),
        )),
    }
}

/// Caddy's health status parsing: `2xx`/`5xx` are status classes written as single digits.
fn parse_health_status(value: &str) -> Result<u16, String> {
    let value = if value.len() == 3 && value.ends_with("xx") {
        &value[..1]
    } else {
        value
    };
    value
        .parse()
        .map_err(|_| format!("invalid status value `{value}`"))
}

fn parse_count(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("`{value}` is not a non-negative integer"))
}

struct ParsedUpstream {
    dial: String,
    https: bool,
    h2c: bool,
}

fn parse_upstreams(target: &str) -> Result<Vec<ParsedUpstream>, String> {
    // Network-specific shorthand: `unix+h2c//path` means a Unix-socket upstream whose transport
    // speaks h2c, and Caddy normalises it to a `unix/...` dial plus an h2c transport.
    if let Some(rest) = target.strip_prefix("unix+h2c//") {
        return Ok(vec![ParsedUpstream {
            dial: format!("unix//{rest}"),
            https: false,
            h2c: true,
        }]);
    }
    // Network addresses (`network/host`, no scheme) are parsed by Caddy's SplitNetworkAddress:
    // everything before the first `/` is the network and the rest is the host verbatim. Unix
    // networks (`unix`, `unixgram`, `unixpacket`, `unix+h2c`) never get a default port appended,
    // and `unix+h2c` is normalised to a `unix/...` dial plus an h2c transport.
    if !target.contains("://") {
        if let Some((network, host)) = target.split_once('/') {
            let network = network.trim().to_ascii_lowercase();
            if network == "unix+h2c" {
                return Ok(vec![ParsedUpstream {
                    dial: format!("unix/{host}"),
                    https: false,
                    h2c: true,
                }]);
            }
            if network.starts_with("unix") {
                return Ok(vec![ParsedUpstream {
                    dial: format!("{network}/{host}"),
                    https: false,
                    h2c: false,
                }]);
            }
        }
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
    // Caddy expands `host:start-end` into one upstream per port, preserving order.
    if let Some((host, ports)) = split_port_range(authority) {
        let mut expanded = Vec::new();
        for port in ports {
            expanded.push(ParsedUpstream {
                dial: format!("{host}:{port}"),
                https: scheme == Some("https"),
                h2c: scheme == Some("h2c"),
            });
        }
        return Ok(expanded);
    }
    let dial = if authority_has_port(authority) || authority.contains('{') {
        // An explicit port stays as written; a placeholder without a port is resolved at request
        // time, so Caddy does not append a default port (it would break `{upstream}` style dials).
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };
    Ok(vec![ParsedUpstream {
        dial,
        https: scheme == Some("https"),
        h2c: scheme == Some("h2c"),
    }])
}

/// Split a `host:start-end` port range into the host and an inclusive list of ports.
fn split_port_range(authority: &str) -> Option<(&str, Vec<u16>)> {
    let (host, range) = authority.rsplit_once(':')?;
    let (start, end) = range.split_once('-')?;
    if start.is_empty() || end.is_empty() {
        return None;
    }
    let start: u16 = start.parse().ok()?;
    let end: u16 = end.parse().ok()?;
    if end < start || end - start > 256 {
        return None;
    }
    Some((host, (start..=end).collect()))
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
        ("{query}", "{http.request.uri.query}"),
        ("{?query}", "{http.request.uri.prefixed_query}"),
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
