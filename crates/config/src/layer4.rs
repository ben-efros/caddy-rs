//! `apps.layer4` adapter for the `layer4 { ... }` global option (ADR-030, T-L4-004).
//!
//! This module converts the [`Layer4Options`] the parser keeps verbatim from
//!
//! ```text
//! layer4 {
//!     0.0.0.0:443 {
//!         @sni tls sni example.com
//!         route @sni {
//!             proxy 127.0.0.1:8443
//!         }
//!     }
//! }
//! ```
//!
//! into the `apps.layer4` JSON object of the upstream `caddy-l4` plugin, for the TCP subset:
//! listener addresses, routes, the `tls` matcher (`sni`, `alpn`), and the `tls`, `proxy_protocol`,
//! `proxy`, `http` and `close` handlers.
//!
//! Two rules shape the emitted JSON:
//!
//! * Unknown keys are rejected with a located error (never forwarded to the runtime): a typo'd
//!   matcher or handler must not silently become a listener that matches nothing.
//! * Fields left at their schema default are omitted, exactly as `caddy-l4` marshals them, so the
//!   output stays byte-identical to upstream for the same Caddyfile.
//!
//! UDP listeners, the remaining matchers/handlers and named route reuse are T-L4-011.
//!
//! ```
//! use caddy_rs_config::layer4::layer4_app_json;
//! let file = caddy_rs_config::parse("{\nlayer4 {\n0.0.0.0:443 {\nclose\n}\n}\n}\n").unwrap();
//! let json = layer4_app_json(file.options.layer4.as_ref().unwrap()).unwrap();
//! assert_eq!(json["servers"]["srv0"]["listen"][0], "0.0.0.0:443");
//! ```

use caddy_rs_core::{Error, Result};
use serde_json::{json, Map, Value};

use crate::lexer::Position;
use crate::parser::{Directive, Layer4Options};

/// Handler directives supported by the TCP subset (`close`, `http`, `tls`, `proxy_protocol`,
/// `proxy`).
const HANDLERS: &[&str] = &[
    "tls",
    "proxy_protocol",
    "proxy",
    "http",
    "close",
    "throttle",
];

/// The `client_auth` modes `caddy-l4` accepts, in its own spelling.
const CLIENT_AUTH_MODES: &[&str] = &[
    "require_and_verify",
    "require",
    "request",
    "verify_if_given",
    "request_and_verify",
];

/// Convert the global `layer4 { ... }` option to Caddy's `apps.layer4` JSON.
///
/// The result is the app object itself (`{"servers": {...}}`), ready to be inserted as
/// `apps.layer4`. Listeners keep their source order and are named `srv0`, `srv1`, ... exactly like
/// the `routes` the upstream Caddyfile parser adds. Errors are located:
///
/// * `Caddyfile line N: confusing layer4 listener address '<...>'` for malformed addresses,
/// * `Caddyfile line N: unknown layer4 <kind> '<name>'` for unknown directives, matchers, handlers
///   or options,
/// * `Caddyfile line N: layer4 ...` for invalid option values or unsupported combinations.
///
/// # Errors
///
/// Returns an [`Error`] carrying the offending [`Position::label`], or one pointing at the
/// `layer4` option itself when the body has no listener block.
pub fn layer4_app_json(options: &Layer4Options) -> Result<Value> {
    if options.directives.is_empty() {
        return Err(error(
            options.position.clone(),
            "layer4: expected at least one listener block, e.g. `0.0.0.0:443 { ... }`",
        ));
    }
    let mut servers = Map::new();
    for (index, directive) in options.directives.iter().enumerate() {
        let listen = listen_address(directive)?;
        let key = format!("srv{index}");
        servers.insert(key, server_json(directive, listen)?);
    }
    Ok(json!({ "servers": Value::Object(servers) }))
}

/// Build one `apps.layer4.servers.<name>` object from a listener block.
///
/// A listener block holds matcher definitions (`@name ...`) and `route ...` statements; with no
/// routing at all it gets the implicit `{"handle": [{"handler": "close"}]}` route, the shape
/// `caddy-l4` produces for a listener that does nothing else.
fn server_json(directive: &Directive, listen: String) -> Result<Value> {
    // Matcher definitions are converted to their `caddy-l4` JSON and referenced by a route as
    // `{"<matcher-type>": {...}}`: the module emits the resolved matcher, not an `@name` reference,
    // so the adapted JSON carries no Caddyfile matcher registry dependency (it is self-contained
    // and matches the `apps.layer4` shape in ADR-030).
    let mut named_matchers: Vec<(String, Value)> = Vec::new();
    let mut routes = Vec::new();

    for inner in &directive.block {
        if let Some(name) = matcher_name(&inner.name) {
            if named_matchers.iter().any(|(known, _)| known == name) {
                return Err(error(
                    inner.position.clone(),
                    format!("layer4: matcher `@{name}` is defined more than once"),
                ));
            }
            let json = matcher_json(name, inner)?;
            named_matchers.push((name.to_string(), json));
        } else if inner.name == "route" {
            routes.push(route_json(inner, &named_matchers)?);
        } else if HANDLERS.contains(&inner.name.as_str()) {
            // A bare handler: wrap it into an implicit route, as the plugin's Caddyfile does.
            routes.push(json!({ "handle": [handler_json(inner)?] }));
        } else {
            return Err(unknown("directive", &inner.name, &inner.position));
        }
    }

    if routes.is_empty() && named_matchers.is_empty() {
        routes.push(json!({ "handle": [{ "handler": "close" }] }));
    }

    let mut server = Map::new();
    server.insert("listen".to_string(), json!([listen]));
    if !routes.is_empty() {
        server.insert("routes".to_string(), Value::Array(routes));
    }
    Ok(Value::Object(server))
}

/// Strip the `@` prefix of a matcher definition name (`@sni` -> `sni`).
fn matcher_name(name: &str) -> Option<&str> {
    name.strip_prefix('@').filter(|name| !name.is_empty())
}

/// Validate a named matcher definition (`@name <matcher> ...`) and return its `caddy-l4` JSON.
///
/// The TCP subset implements the `tls` matcher only (`sni` and `alpn` patterns); every other
/// matcher (`http`, `postgres`, `ssh`, ...) is a located "unsupported" error tagged T-L4-011.
fn matcher_json(name: &str, directive: &Directive) -> Result<Value> {
    if !directive.block.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!("layer4: matcher `@{name}` does not take a block"),
        ));
    }
    let Some((matcher, args)) = directive.args.split_first() else {
        return Err(error(
            directive.position.clone(),
            format!("layer4: matcher `@{name}` has no matcher name, e.g. `tls sni <domain>`"),
        ));
    };
    let matcher = matcher.strip_prefix("l4.").unwrap_or(matcher);
    match matcher {
        "tls" => Ok(json!({ "tls": tls_matcher_json(name, args, directive)? })),
        "remote_ip" | "ip" => {
            Ok(json!({ "remote_ip": { "ranges": any_patterns(name, args, directive)? } }))
        }
        "asn" => {
            let mut numbers = Vec::new();
            for arg in args {
                let asn: u32 = arg.parse().map_err(|_| {
                    error(
                        directive.position.clone(),
                        format!("layer4: `@{name}` ASN `{arg}` is not an unsigned 32-bit number"),
                    )
                })?;
                numbers.push(Value::from(asn));
            }
            if numbers.is_empty() {
                return Err(error(
                    directive.position.clone(),
                    format!("layer4: `@{name}` needs at least one ASN"),
                ));
            }
            Ok(json!({ "asn": Value::Array(numbers) }))
        }
        "ssh" | "http" | "proxy_protocol" => {
            if !args.is_empty() {
                return Err(unsupported(
                    directive.position.clone(),
                    format!("layer4: matcher `@{name}` option `{}`", args[0]),
                ));
            }
            Ok(json!({ matcher: Map::new() }))
        }
        other => Err(unsupported(
            directive.position.clone(),
            format!("layer4: matcher `@{name}` uses `{other}`"),
        )),
    }
}

/// Matcher arguments taken verbatim (IP ranges, SNI/ALPN-style patterns).
fn any_patterns(name: &str, args: &[String], directive: &Directive) -> Result<Vec<String>> {
    if args.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!("layer4: `@{name}` needs at least one argument"),
        ));
    }
    Ok(args.to_vec())
}

/// The `tls` matcher options object: `{"sni": [...], "alpn": [...]}`, defaults omitted.
fn tls_matcher_json(name: &str, args: &[String], directive: &Directive) -> Result<Value> {
    let mut object = Map::new();
    let mut index = 0;
    while let Some(option) = args.get(index) {
        index += 1;
        match option.as_str() {
            "sni" => {
                let patterns = take_patterns(name, "sni", args, &mut index, directive)?;
                object.insert("sni".to_string(), json!(patterns));
            }
            "alpn" => {
                let patterns = take_patterns(name, "alpn", args, &mut index, directive)?;
                object.insert("alpn".to_string(), json!(patterns));
            }
            other => {
                return Err(unsupported(
                    directive.position.clone(),
                    format!("layer4: `tls` matcher option `{other}` in `@{name}`"),
                ));
            }
        }
    }
    Ok(Value::Object(object))
}

/// Collect the patterns that follow a `sni`/`alpn` keyword up to the next option keyword.
///
/// `sni` accepts exact names (`example.com`), leading-label wildcards (`*.example.com`), and a
/// parenthesised group (`(a.com b.com)`, or a shared `(a.com` / `b.com)` pair). Each pattern is
/// validated so a typo'd wildcard is a located error rather than a listener that never matches.
fn take_patterns(
    name: &str,
    option: &str,
    args: &[String],
    index: &mut usize,
    directive: &Directive,
) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    while let Some(arg) = args.get(*index) {
        if is_option_keyword(arg) {
            break;
        }
        *index += 1;
        for pattern in group_patterns(name, option, arg, directive)? {
            validate_pattern(name, option, &pattern, directive)?;
            patterns.push(pattern);
        }
    }
    if patterns.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!("layer4: `{option}` in `@{name}` needs at least one pattern"),
        ));
    }
    Ok(patterns)
}

/// Split one pattern argument, which may be a parenthesised group token.
fn group_patterns(
    name: &str,
    option: &str,
    arg: &str,
    directive: &Directive,
) -> Result<Vec<String>> {
    let trimmed = arg;
    let open = trimmed.starts_with('(');
    let close = trimmed.ends_with(')');
    match (open, close) {
        (true, true) => Ok(trimmed[1..trimmed.len() - 1]
            .split_whitespace()
            .map(str::to_string)
            .collect()),
        // A group that opens in one token and closes in a later one is collected by `take_patterns`
        // only when it spans quoting; the lexer keeps `(a.com` and `b.com)` separate, so accept
        // the partial forms with the parentheses stripped.
        (true, false) => Ok(trimmed[1..]
            .split_whitespace()
            .map(str::to_string)
            .collect()),
        (false, true) => Ok(trimmed[..trimmed.len() - 1]
            .split_whitespace()
            .map(str::to_string)
            .collect()),
        (false, false) if trimmed.contains('(') || trimmed.contains(')') => Err(error(
            directive.position.clone(),
            format!("layer4: stray parenthesis in `{option}` pattern `{trimmed}` in `@{name}`"),
        )),
        (false, false) => Ok(vec![trimmed.to_string()]),
    }
}

/// Option keywords that end a `sni`/`alpn` pattern list.
fn is_option_keyword(arg: &str) -> bool {
    matches!(arg, "sni" | "alpn")
}

/// Validate one `sni`/`alpn` pattern: DNS names, a leading `*.` wildcard, and ALPN protocol ids.
fn validate_pattern(name: &str, option: &str, pattern: &str, directive: &Directive) -> Result<()> {
    if pattern.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!("layer4: empty `{option}` pattern in `@{name}`"),
        ));
    }
    if option == "alpn" {
        // ALPN protocol ids are opaque but printable (RFC 7301); whitespace and control
        // characters can only come from a quoting mistake.
        if pattern.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(error(
                directive.position.clone(),
                format!("layer4: invalid alpn pattern `{pattern}` in `@{name}`"),
            ));
        }
        return Ok(());
    }
    let host = pattern.strip_prefix("*.").unwrap_or(pattern);
    if host.is_empty() || host.contains('*') {
        return Err(error(
            directive.position.clone(),
            format!(
                "layer4: invalid sni pattern `{pattern}` in `@{name}`: a wildcard is only \
                 allowed as the leading `*.` label"
            ),
        ));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        // `caddy-l4` accepts literal addresses in `sni`; nothing more to validate.
        return Ok(());
    }
    let valid = host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if !valid {
        return Err(error(
            directive.position.clone(),
            format!("layer4: invalid sni pattern `{pattern}` in `@{name}`: not a DNS name"),
        ));
    }
    Ok(())
}

/// Convert a `route` statement to a `caddy-l4` route.
///
/// `route @a @b { ... }` yields `{"match": [{"@a": null}, {"@b": null}], "handle": [...]}`; a route
/// without matcher references omits `match`, matching the plugin's `omitempty` marshalling.
fn route_json(directive: &Directive, named_matchers: &[(String, Value)]) -> Result<Value> {
    let mut matches = Vec::new();
    for arg in &directive.args {
        let Some(name) = matcher_name(arg) else {
            return Err(error(
                directive.position.clone(),
                format!(
                    "layer4: `route` argument `{arg}` is not a matcher reference: expected `@name`"
                ),
            ));
        };
        let Some((_, matcher)) = named_matchers.iter().find(|(known, _)| known == name) else {
            return Err(error(
                directive.position.clone(),
                format!("layer4: `route` references undefined matcher `@{name}`"),
            ));
        };
        matches.push(matcher.clone());
    }
    if directive.block.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `route` needs at least one handler",
        ));
    }
    let mut handle = Vec::new();
    for inner in &directive.block {
        handle.push(handler_json(inner)?);
    }
    let mut route = Map::new();
    if !matches.is_empty() {
        route.insert("match".to_string(), Value::Array(matches));
    }
    route.insert("handle".to_string(), Value::Array(handle));
    Ok(Value::Object(route))
}

/// Convert one handler directive to its `caddy-l4` JSON object (`{"handler": "<name>", ...}`).
fn handler_json(directive: &Directive) -> Result<Value> {
    match directive.name.as_str() {
        "close" => {
            if !directive.args.is_empty() || !directive.block.is_empty() {
                return Err(error(
                    directive.position.clone(),
                    "layer4: `close` takes no arguments or block",
                ));
            }
            Ok(json!({ "handler": "close" }))
        }
        "http" => http_handler_json(directive),
        "tls" => tls_handler_json(directive),
        "proxy_protocol" => proxy_protocol_handler_json(directive),
        "proxy" => proxy_handler_json(directive),
        "throttle" => throttle_handler_json(directive),
        other => Err(unknown("handler", other, &directive.position)),
    }
}

/// `tls [client_auth <ca>...]` -> `{"handler": "tls", ...}`.
///
/// `client_auth` is the one option of the TCP subset; it is emitted as
/// `connection_policies[0].client_authentication.ca`. Every other option (`alpn`, `match`,
/// `handshake_timeout`, `connection_policy`, inline `{ ... }`) is a located error, not a silently
/// dropped option.
fn tls_handler_json(directive: &Directive) -> Result<Value> {
    if !directive.block.is_empty() {
        return tls_handler_block_json(directive);
    }
    if directive.args.is_empty() {
        return Ok(json!({ "handler": "tls" }));
    }
    // `tls client_auth <ca>...`: `client_auth` is the option keyword and the CA paths follow it,
    // so the line is three or more words (the Caddyfile form used by ADR-030's example).
    if directive.args.first().map(String::as_str) != Some("client_auth") {
        let option = directive.args.first();
        return Err(unsupported(
            directive.position.clone(),
            format!(
                "layer4: `tls` handler option `{}`",
                option.map(String::as_str).unwrap_or("client_auth")
            ),
        ));
    }
    // `tls client_auth <ca>...`: the CA list follows the keyword to the end of the line. Module
    // forms (`trusted_ca_certs`, `trusted_ca_pool`) and the `require`/`request` modes of newer
    // caddy-l4 releases are T-L4-011.
    let cas = &directive.args[1..];
    if cas.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `tls client_auth` needs at least one CA file path",
        ));
    }
    // ADR-030's example spells client auth as `client_auth.mode` + `client_auth.trusted_ca_cert_file`
    // (`require_and_verify` with a trusted CA bundle). The Caddyfile form supplies only the CA
    // path, so the mode defaults to `require_and_verify`; a leading mode word overrides it.
    let (mode, cas) = match cas.split_first() {
        Some((first, rest))
            if *first == "require_and_verify" || *first == "request" || *first == "require" =>
        {
            (first.clone(), rest)
        }
        _ => ("require_and_verify".to_string(), cas),
    };
    if cas.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `tls client_auth` needs at least one CA file path",
        ));
    }
    let mut client_auth = Map::new();
    client_auth.insert("mode".to_string(), json!(mode));
    client_auth.insert(
        "trusted_ca_cert_file".to_string(),
        Value::Array(cas.iter().map(|ca| json!(ca)).collect()),
    );
    Ok(json!({ "handler": "tls", "client_auth": Value::Object(client_auth) }))
}

/// `tls { client_auth { ... } }` -> `{"handler": "tls", "client_auth": {...}}`.
///
/// This is the block form ADR-031's configuration example uses, and it is the only way to express
/// `client_auth` as an object rather than the one-line `tls client_auth <ca>...` shorthand. The
/// emitted shape is `client_auth.mode` plus `client_auth.trusted_ca_cert_file`, matching the
/// `apps.layer4` JSON in ADR-031 §"JSON (`apps.layer4`)".
///
/// Accepted sub-options:
/// * `client_auth { mode <mode>; trusted_ca_cert_file <path>... }` — `mode` defaults to
///   `require_and_verify` when omitted, which is what the shorthand form also defaults to, so the
///   two spellings of the same intent agree.
///
/// Anything else is a located error naming the sub-option, never a silently dropped key: an
/// unknown `tls` option that loaded quietly would leave an operator believing a handshake
/// constraint was applied when it was not.
fn tls_handler_block_json(directive: &Directive) -> Result<Value> {
    if !directive.args.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!(
                "layer4: `tls` handler takes either arguments or a block, not both (got `{}`)",
                directive.args.join(" ")
            ),
        ));
    }
    let mut handler = Map::new();
    handler.insert("handler".to_string(), json!("tls"));
    for inner in &directive.block {
        match inner.name.as_str() {
            "client_auth" => {
                handler.insert("client_auth".to_string(), tls_client_auth_json(inner)?);
            }
            other => {
                return Err(unknown("`tls` handler option", other, &inner.position));
            }
        }
    }
    Ok(Value::Object(handler))
}

/// The `client_auth { ... }` sub-block of the `tls` handler.
///
/// `mode` accepts the `caddy-l4` mode names (`require_and_verify`, `require`, `request`, `verify_if_given`,
/// `request_and_verify`); an unrecognised mode is a located error rather than being passed through,
/// because a typo in a security-relevant mode must not reach the runtime.
fn tls_client_auth_json(directive: &Directive) -> Result<Value> {
    if !directive.args.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!(
                "layer4: `client_auth` takes a block, not arguments (got `{}`)",
                directive.args.join(" ")
            ),
        ));
    }
    let mut client_auth = Map::new();
    let mut mode: Option<String> = None;
    let mut cas: Vec<Value> = Vec::new();
    for inner in &directive.block {
        match inner.name.as_str() {
            "mode" => {
                let Some(value) = inner.args.first() else {
                    return Err(error(
                        inner.position.clone(),
                        "layer4: `client_auth mode` needs a value",
                    ));
                };
                if inner.args.len() > 1 {
                    return Err(error(
                        inner.position.clone(),
                        format!(
                            "layer4: `client_auth mode` takes exactly one value, got `{}`",
                            inner.args.join(" ")
                        ),
                    ));
                }
                if !CLIENT_AUTH_MODES.contains(&value.as_str()) {
                    return Err(error(
                        inner.position.clone(),
                        format!(
                            "layer4: `client_auth mode` `{value}` is not one of {}",
                            CLIENT_AUTH_MODES.join(", ")
                        ),
                    ));
                }
                mode = Some(value.clone());
            }
            "trusted_ca_cert_file" => {
                if inner.args.is_empty() {
                    return Err(error(
                        inner.position.clone(),
                        "layer4: `client_auth trusted_ca_cert_file` needs at least one path",
                    ));
                }
                cas.extend(inner.args.iter().map(|ca| json!(ca)));
            }
            other => {
                return Err(unknown("`client_auth` option", other, &inner.position));
            }
        }
    }
    client_auth.insert(
        "mode".to_string(),
        json!(mode.unwrap_or_else(|| "require_and_verify".to_string())),
    );
    if !cas.is_empty() {
        client_auth.insert("trusted_ca_cert_file".to_string(), Value::Array(cas));
    }
    Ok(Value::Object(client_auth))
}

/// `proxy_protocol [v1|v2]` -> `{"handler": "proxy_protocol", "version": "v2"}`.
///
/// The default is `v1`, which the plugin omits: `proxy_protocol` and `proxy_protocol v1` both
/// adapt to `{"handler": "proxy_protocol"}`, and `v2` adds `"version": "v2"`.
fn proxy_protocol_handler_json(directive: &Directive) -> Result<Value> {
    if !directive.block.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `proxy_protocol` does not take a block",
        ));
    }
    match directive.args.as_slice() {
        [] => Ok(json!({ "handler": "proxy_protocol" })),
        [version] if version == "v1" => Ok(json!({ "handler": "proxy_protocol" })),
        [version] if version == "v2" => Ok(json!({ "handler": "proxy_protocol", "version": "v2" })),
        [other] => Err(error(
            directive.position.clone(),
            format!("layer4: `proxy_protocol` version `{other}` is invalid: expected `v1` or `v2`"),
        )),
        _ => Err(error(
            directive.position.clone(),
            "layer4: `proxy_protocol` takes at most one argument (`v1` or `v2`)",
        )),
    }
}

/// `throttle { upstream <rate>; downstream <rate> }` -> `{"handler": "throttle", ...}`.
///
/// The emitted keys are exactly the field names of the runtime `RateLimit` handler in
/// `crates/l4/src/handlers/throttle.rs` (`upstream_bytes_per_second`,
/// `downstream_bytes_per_second`), so the adapted JSON decodes into that struct without a
/// translation layer.
///
/// Rates are bytes per second. A bare number is taken as bytes per second; an `SI`/`IEC` suffix
/// (`500KB`, `2MiB`, `1GB`) is accepted because a Caddyfile rate in raw bytes is unreadable and
/// every operator writes a suffix. A rate of zero is rejected: it would mean "block all traffic",
/// which is what `close` is for, and silently throttling to zero is never what an operator means.
fn throttle_handler_json(directive: &Directive) -> Result<Value> {
    if !directive.args.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!(
                "layer4: `throttle` takes a block with `upstream` and/or `downstream`, not \
                 arguments (got `{}`)",
                directive.args.join(" ")
            ),
        ));
    }
    if directive.block.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `throttle` needs a block, e.g. `throttle { upstream 10MB; downstream 50MB }`",
        ));
    }
    let mut handler = Map::new();
    handler.insert("handler".to_string(), json!("throttle"));
    for inner in &directive.block {
        let key = match inner.name.as_str() {
            "upstream" => "upstream_bytes_per_second",
            "downstream" => "downstream_bytes_per_second",
            other => {
                return Err(unknown("`throttle` option", other, &inner.position));
            }
        };
        if inner.args.len() != 1 {
            return Err(error(
                inner.position.clone(),
                format!(
                    "layer4: `throttle {}` takes exactly one rate, got `{}`",
                    inner.name,
                    inner.args.join(" ")
                ),
            ));
        }
        let rate = parse_byte_rate(&inner.args[0], &inner.position)?;
        if handler.contains_key(key) {
            return Err(error(
                inner.position.clone(),
                format!("layer4: `throttle {}` is set more than once", inner.name),
            ));
        }
        handler.insert(key.to_string(), json!(rate));
    }
    if handler.len() == 1 {
        return Err(error(
            directive.position.clone(),
            "layer4: `throttle` needs at least one of `upstream` or `downstream`",
        ));
    }
    Ok(Value::Object(handler))
}

/// Parse a byte rate: a bare byte count, or a number with an `SI` (`KB`/`MB`/`GB`) or `IEC`
/// (`KiB`/`MiB`/`GiB`) suffix. Case-insensitive, and a trailing `/s` is allowed and ignored so
/// `10MB/s` reads naturally.
fn parse_byte_rate(text: &str, position: &Position) -> Result<u64> {
    let t = text.trim();
    let t = t.strip_suffix("/s").unwrap_or(t);
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, suffix) = t.split_at(split);
    if digits.is_empty() {
        return Err(error(
            position.clone(),
            format!("layer4: `throttle` rate `{text}` does not start with a number"),
        ));
    }
    let value: u64 = digits.parse().map_err(|_| {
        error(
            position.clone(),
            format!("layer4: `throttle` rate `{text}` has an unparsable number `{digits}`"),
        )
    })?;
    let multiplier: u64 = match suffix.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" => 1_000,
        "M" | "MB" => 1_000_000,
        "G" | "GB" => 1_000_000_000,
        "KIB" => 1_024,
        "MIB" => 1_048_576,
        "GIB" => 1_073_741_824,
        other => {
            return Err(error(
                position.clone(),
                format!(
                    "layer4: `throttle` rate `{text}` has an unknown suffix `{other}`; use B, KB, \
                     MB, GB or KiB, MiB, GiB"
                ),
            ));
        }
    };
    let rate = value.checked_mul(multiplier).ok_or_else(|| {
        error(
            position.clone(),
            format!("layer4: `throttle` rate `{text}` overflows a byte count"),
        )
    })?;
    if rate == 0 {
        return Err(error(
            position.clone(),
            "layer4: `throttle` rate must be greater than zero; use `close` to reject traffic",
        ));
    }
    Ok(rate)
}

/// `proxy <upstream>...` -> `{"handler": "proxy", "upstreams": [{"dial": "<upstream>"}]}`.
///
/// The TCP subset takes dial addresses only; `lb_policy`, `health_checks` and the inline
/// `{ ... }` block are options the plugin adds in T-L4-011.
fn proxy_handler_json(directive: &Directive) -> Result<Value> {
    if !directive.block.is_empty() {
        return Err(unsupported(
            directive.position.clone(),
            "layer4: inline `proxy { ... }` options",
        ));
    }
    if directive.args.is_empty() {
        return Err(error(
            directive.position.clone(),
            "layer4: `proxy` needs at least one upstream address to dial",
        ));
    }
    let mut upstreams = Vec::new();
    for upstream in &directive.args {
        validate_dial(upstream, &directive.position)?;
        upstreams.push(json!({ "dial": upstream }));
    }
    Ok(json!({ "handler": "proxy", "upstreams": Value::Array(upstreams) }))
}

/// `http` -> `{"handler": "http", "tls": false}`.
///
/// The plugin's `http` handler takes no arguments; its optional `{ tls }` block wraps the stream
/// in TLS toward the HTTP server, which the TCP subset does not implement yet.
fn http_handler_json(directive: &Directive) -> Result<Value> {
    if !directive.args.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!(
                "layer4: `http` takes no arguments (unexpected `{}`)",
                directive.args[0]
            ),
        ));
    }
    if !directive.block.is_empty() {
        return Err(unsupported(
            directive.position.clone(),
            "layer4: inline `http { ... }` options",
        ));
    }
    Ok(json!({ "handler": "http", "tls": false }))
}

/// Validate a dial address (`host:port` or `[v6]:port`).
fn validate_dial(upstream: &str, position: &Position) -> Result<()> {
    let Some((host, port)) = split_host_port(upstream) else {
        return Err(error(
            position.clone(),
            format!(
                "layer4: invalid `proxy` upstream `{upstream}`: expected `host:port` or \
                 `[ipv6]:port`"
            ),
        ));
    };
    // An empty host is written as `:port`, which Caddy and Go accept (`net.Dial("tcp", ":2222")`
    // resolves to the local host), and ADR-030's own example uses it; `split_host_port` above
    // already rejects a value with no `:` at all, so nothing more to reject here.
    if host.is_empty() && port.is_empty() {
        return Err(error(
            position.clone(),
            format!("layer4: invalid `proxy` upstream `{upstream}`: empty host"),
        ));
    }
    parse_port(&port, position, upstream)?;
    Ok(())
}

/// Split a `host:port` / `[v6]:port` address into its host and port strings.
fn split_host_port(address: &str) -> Option<(String, String)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host.to_string(), port.to_string()));
    }
    let (host, port) = address.rsplit_once(':')?;
    Some((host.to_string(), port.to_string()))
}

/// Parse a `0..=65535` port, returning a located error naming `address` otherwise.
///
/// Port `0` is accepted: it is the plugin's way to let the OS pick, and the runtime validator
/// rejects only listeners it cannot bind.
fn parse_port(port: &str, position: &Position, address: &str) -> Result<u16> {
    port.parse::<u16>().map_err(|_| {
        error(
            position.clone(),
            format!(
                "confusing layer4 listener/upstream address `{address}`: port `{port}` is not a \
                 number between 0 and 65535"
            ),
        )
    })
}

/// A listener block's address -> the single `listen` element of its server.
///
/// Both the TCP form (`host:port`) and the UDP forms are accepted. `caddy-l4` spells a UDP listener
/// three ways in a Caddyfile, and all three mean the same thing:
///
/// * `host:port/udp` — the network as a suffix, which is the form ADR-031 documents and the form
///   `listen` itself uses in the emitted JSON (`"0.0.0.0:51820/udp"`);
/// * `udp/host:port` — the network as a prefix;
/// * `udp:host:port` — the network as a scheme-like prefix.
///
/// All three normalise to the single canonical `host:port/udp` spelling in `listen`, so the adapted
/// JSON does not depend on which spelling the operator chose. A TCP address that merely mentions
/// "udp" is not mistaken for one: only these three exact shapes are recognised, and a bare
/// `host:port` stays TCP.
fn listen_address(directive: &Directive) -> Result<String> {
    // The Caddyfile lexer ends a word at `:`, so a `host:port` listener arrives split across the
    // directive name and its arguments (`name = "0.0.0.0"`, `args = [":443"]`). Rejoin them exactly
    // as written, then split cleanly: that is the key difference from an L7 site address block,
    // where the port is part of the address key.
    let raw = std::iter::once(directive.name.as_str())
        .chain(directive.args.iter().map(String::as_str))
        .collect::<String>();
    // Split off a UDP network marker before validating the address, so every accepted spelling
    // reduces to one canonical form. `udp:` is checked before `udp/` because it is the shorter
    // prefix and both are unambiguous at position 0.
    let (address, udp) = if let Some(rest) = raw.strip_suffix("/udp") {
        (rest.to_string(), true)
    } else if let Some(rest) = raw.strip_prefix("udp/") {
        (rest.to_string(), true)
    } else if let Some(rest) = raw.strip_prefix("udp:") {
        (rest.to_string(), true)
    } else {
        (raw.clone(), false)
    };
    let address = address.as_str();
    let Some((host, port)) = split_host_port(address) else {
        return Err(error(
            directive.position.clone(),
            format!(
                "confusing layer4 listener address `{address}`: expected `host:port`, \
                 `[ipv6]:port`, or a UDP form `host:port/udp`, `udp/host:port`, `udp:host:port`"
            ),
        ));
    };
    if host.is_empty() {
        return Err(error(
            directive.position.clone(),
            format!("confusing layer4 listener address `{address}`: empty host"),
        ));
    }
    parse_port(&port, &directive.position, address)?;
    if host.parse::<std::net::IpAddr>().is_err() && !valid_hostname(&host) {
        return Err(error(
            directive.position.clone(),
            format!("confusing layer4 listener address `{address}`: `{host}` is not a host"),
        ));
    }
    // Canonicalise to the suffix spelling, which is what `listen` itself uses.
    Ok(if udp {
        format!("{address}/udp")
    } else {
        address.to_string()
    })
}

/// A permissive hostname check for listener hosts (`localhost`, zone-free DNS names).
fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A located `invalid configuration` error.
fn error(position: Position, message: impl Into<String>) -> Error {
    Error::invalid(position.label(), message.into())
}

/// A located `unsupported` error: a `caddy-l4` feature the TCP subset does not implement yet.
fn unsupported(position: Position, feature: impl Into<String>) -> Error {
    Error::unsupported(position.label(), feature.into(), "T-L4-011")
}

/// A located `unknown key` error for an unknown directive, matcher or handler.
fn unknown(kind: &str, name: &str, position: &Position) -> Error {
    error(position.clone(), format!("unknown layer4 {kind} `{name}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapt(source: &str) -> Result<Value> {
        let file = crate::parse(source).expect("parse");
        layer4_app_json(file.options.layer4.as_ref().expect("layer4 option"))
    }

    #[test]
    fn listener_adapts_to_servers_with_listen() {
        let json = adapt("{\nlayer4 {\n0.0.0.0:443 {\nclose\n}\n}\n}\n").unwrap();
        assert_eq!(
            json,
            json!({
                "servers": {
                    "srv0": {
                        "listen": ["0.0.0.0:443"],
                        "routes": [{ "handle": [{ "handler": "close" }] }],
                    }
                }
            })
        );
    }

    #[test]
    fn empty_listener_gets_implicit_close_route() {
        let json = adapt("{\nlayer4 {\n0.0.0.0:443\n}\n}\n").unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"],
            json!([{ "handle": [{ "handler": "close" }] }])
        );
    }

    #[test]
    fn sni_matcher_parses_exact_and_wildcard_patterns() {
        let json = adapt(
            "{\nlayer4 {\n0.0.0.0:443 {\n@sni tls sni example.com *.example.org\nroute @sni {\nclose\n}\n}\n}\n}\n",
        )
        .unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["match"],
            json!([{ "tls": { "sni": ["example.com", "*.example.org"] } }])
        );
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"],
            json!([{ "handler": "close" }])
        );
    }

    #[test]
    fn sni_matcher_accepts_multiple_names_and_groups() {
        let json = adapt(
            "{\nlayer4 {\n0.0.0.0:443 {\n@sni tls sni (a.example.com b.example.com) *.example.org\nroute @sni {\nclose\n}\n}\n}\n}\n",
        )
        .unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["match"],
            json!([{ "tls": { "sni": ["a.example.com", "b.example.com", "*.example.org"] } }])
        );
    }

    #[test]
    fn alpn_matcher_parses() {
        let json = adapt(
            "{\nlayer4 {\n0.0.0.0:443 {\n@h2 tls alpn h2 h2c\nroute @h2 {\nclose\n}\n}\n}\n}\n",
        )
        .unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["match"],
            json!([{ "tls": { "alpn": ["h2", "h2c"] } }])
        );
    }

    #[test]
    fn handlers_adapt_one_to_one() {
        let json = adapt(
            "{\nlayer4 {\n0.0.0.0:443 {\nroute {\ntls\nproxy_protocol v2\nproxy 127.0.0.1:8443\nhttp\nclose\n}\n}\n}\n}\n",
        )
        .unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"],
            json!([
                { "handler": "tls" },
                { "handler": "proxy_protocol", "version": "v2" },
                { "handler": "proxy", "upstreams": [{ "dial": "127.0.0.1:8443" }] },
                { "handler": "http", "tls": false },
                { "handler": "close" }
            ])
        );
    }

    #[test]
    fn tls_handler_client_auth_adapts() {
        let json =
            adapt("{\nlayer4 {\n0.0.0.0:443 {\nroute {\ntls client_auth /etc/ca.pem\n}\n}\n}\n}\n")
                .unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"][0],
            json!({
                "handler": "tls",
                "client_auth": { "mode": "require_and_verify", "trusted_ca_cert_file": ["/etc/ca.pem"] }
            })
        );
    }

    #[test]
    fn proxy_protocol_v1_is_default_and_omitted() {
        let json = adapt("{\nlayer4 {\n0.0.0.0:443 {\nproxy_protocol v1\n}\n}\n}\n").unwrap();
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"][0],
            json!({ "handler": "proxy_protocol" })
        );
    }

    #[test]
    fn multiple_listeners_keep_source_order() {
        let json =
            adapt("{\nlayer4 {\n0.0.0.0:443 {\nclose\n}\n[::]:8443 {\nclose\n}\n}\n}\n").unwrap();
        assert_eq!(
            json["servers"],
            json!({
                "srv0": { "listen": ["0.0.0.0:443"], "routes": [{ "handle": [{ "handler": "close" }] }] },
                "srv1": { "listen": ["[::]:8443"], "routes": [{ "handle": [{ "handler": "close" }] }] },
            })
        );
    }

    #[test]
    fn unknown_directive_is_located() {
        let err = adapt("{\nlayer4 {\n0.0.0.0:443 {\nfrobnicate\n}\n}\n}\n").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Caddyfile line 4"), "{text}");
        assert!(
            text.contains("unknown layer4 directive `frobnicate`"),
            "{text}"
        );
    }

    #[test]
    fn unknown_matcher_is_located() {
        let err = adapt("{\nlayer4 {\n0.0.0.0:443 {\n@x bogus foo\n}\n}\n}\n").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Caddyfile line 4"), "{text}");
        assert!(text.contains("bogus"), "{text}");
    }

    #[test]
    fn malformed_listen_address_is_located() {
        for address in ["0.0.0.0", "0.0.0.0:notaport", "0.0.0.0:70000", "0.0.0.0:"] {
            let source = format!("{{\nlayer4 {{\n{address} {{\nclose\n}}\n}}\n}}\n");
            let err = adapt(&source).unwrap_err();
            let text = err.to_string();
            assert!(text.contains("Caddyfile line 3"), "{address}: {text}");
            assert!(
                text.contains("confusing layer4 listener"),
                "{address}: {text}"
            );
        }
    }

    #[test]
    fn invalid_option_values_are_located() {
        let err = adapt("{\nlayer4 {\n0.0.0.0:443 {\nproxy_protocol v3\n}\n}\n}\n").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Caddyfile line 4"), "{text}");
        assert!(text.contains("version `v3` is invalid"), "{text}");

        let err =
            adapt("{\nlayer4 {\n0.0.0.0:443 {\n@sni tls sni bad*name.com\n}\n}\n}\n").unwrap_err();
        assert!(err.to_string().contains("invalid sni pattern"), "{err}");

        let err = adapt("{\nlayer4 {\n0.0.0.0:443 {\ntls bogus\n}\n}\n}\n").unwrap_err();
        assert!(
            err.to_string().contains("`tls` handler option `bogus`"),
            "{err}"
        );
    }

    #[test]
    fn udp_listener_adapts_and_normalises_every_spelling() {
        // T-L4-004 rejected UDP with a tracking id; T-L4-011 implements it. All three caddy-l4
        // Caddyfile spellings must produce the SAME `listen` element, because the emitted JSON must
        // not depend on which spelling the operator chose.
        for spelling in ["0.0.0.0:443/udp", "udp/0.0.0.0:443", "udp:0.0.0.0:443"] {
            let config = adapt(&format!(
                "{{\nlayer4 {{\n{spelling} {{\nclose\n}}\n}}\n}}\n"
            ))
            .unwrap_or_else(|e| panic!("`{spelling}` must adapt: {e}"));
            let server = config["servers"]["srv0"].clone();
            assert_eq!(
                server["listen"],
                json!(["0.0.0.0:443/udp"]),
                "`{spelling}` must normalise to the canonical UDP listen form"
            );
            assert_eq!(
                server["routes"],
                json!([{ "handle": [{ "handler": "close" }] }]),
                "`{spelling}` must keep its routes"
            );
        }
    }

    #[test]
    fn a_tcp_listener_is_not_mistaken_for_udp() {
        // The normalisation must not fire on an address that merely contains "udp" somewhere.
        let config = adapt("{\nlayer4 {\n0.0.0.0:443 {\nclose\n}\n}\n}\n").unwrap();
        assert_eq!(config["servers"]["srv0"]["listen"], json!(["0.0.0.0:443"]));
    }

    #[test]
    fn the_adr_030_example_block_adapts() {
        // ADR-030's own Caddyfile example (docs/adr/0030-l4-tls-sni-routing.md, "Caddyfile
        // (Global `layer4` Block)"), reduced to its TCP listener. Every matcher and handler it
        // uses must adapt; a subset that cannot carry the ADR's example is not parity.
        let source = concat!(
            "{\n",
            "layer4 {\n",
            "0.0.0.0:443 {\n",
            "@blocked_asns asn 16509 14061\n",
            "@blocked_ips remote_ip 192.0.2.0/24\n",
            "route @blocked_asns @blocked_ips {\n",
            "close\n",
            "}\n",
            "@ssh_sni tls sni ssh.example.com\n",
            "route @ssh_sni {\n",
            "tls client_auth require_and_verify /etc/caddy/ssh-ca.pem\n",
            "proxy_protocol v2\n",
            "proxy 127.0.0.1:22\n",
            "}\n",
            "@passthrough tls sni internal.example.com\n",
            "route @passthrough {\n",
            "proxy 10.0.0.12:8443\n",
            "}\n",
            "@web tls sni *.web.example.com\n",
            "route @web {\n",
            "http\n",
            "}\n",
            "route {\n",
            "proxy :2222\n",
            "}\n",
            "}\n",
            "}\n",
            "}\n",
        );
        let json = adapt(source).unwrap();
        let routes = &json["servers"]["srv0"]["routes"];
        assert_eq!(
            routes[0]["match"],
            json!([{ "asn": [16509, 14061] }, { "remote_ip": { "ranges": ["192.0.2.0/24"] } }])
        );
        assert_eq!(routes[0]["handle"], json!([{ "handler": "close" }]));
        assert_eq!(
            routes[1]["match"],
            json!([{ "tls": { "sni": ["ssh.example.com"] } }])
        );
        assert_eq!(
            routes[1]["handle"],
            json!([
                {
                    "handler": "tls",
                    "client_auth": {
                        "mode": "require_and_verify",
                        "trusted_ca_cert_file": ["/etc/caddy/ssh-ca.pem"]
                    }
                },
                { "handler": "proxy_protocol", "version": "v2" },
                { "handler": "proxy", "upstreams": [{ "dial": "127.0.0.1:22" }] }
            ])
        );
        assert_eq!(
            routes[2]["match"],
            json!([{ "tls": { "sni": ["internal.example.com"] } }])
        );
        assert_eq!(
            routes[2]["handle"],
            json!([{ "handler": "proxy", "upstreams": [{ "dial": "10.0.0.12:8443" }] }])
        );
        assert_eq!(
            routes[3]["match"],
            json!([{ "tls": { "sni": ["*.web.example.com"] } }])
        );
        assert_eq!(
            routes[3]["handle"],
            json!([{ "handler": "http", "tls": false }])
        );
        // The fallback route has no matchers and therefore no `match` key.
        assert_eq!(
            routes[4],
            json!({ "handle": [{ "handler": "proxy", "upstreams": [{ "dial": ":2222" }] }] })
        );
    }

    #[test]
    fn ip_asn_and_banner_matchers_adapt() {
        let json = adapt(concat!(
            "{\nlayer4 {\n0.0.0.0:443 {\n",
            "@ns asn 64512\n",
            "@ranges remote_ip 10.0.0.0/8 2001:db8::/32\n",
            "@shell ssh\n",
            "@web http\n",
            "@pp proxy_protocol\n",
            "}\n}\n}\n",
        ))
        .unwrap();
        // A listener holding matcher *definitions* but no route has no routes: the definitions only
        // matter through a `route @name` reference (a matcher alone cannot route anything).
        assert_eq!(json["servers"]["srv0"]["routes"], Value::Null);
        // Each matcher shape is reachable from a route reference; covered end-to-end above for
        // `tls`, so assert the remaining shapes adapt through the same path here.
        let reference = adapt(concat!(
            "{\nlayer4 {\n0.0.0.0:443 {\n",
            "@ns asn 64512\n",
            "@ranges remote_ip 10.0.0.0/8 2001:db8::/32\n",
            "@shell ssh\n",
            "@web http\n",
            "@pp proxy_protocol\n",
            "route @ns @ranges @shell @web @pp {\nclose\n}\n",
            "}\n}\n}\n",
        ))
        .unwrap();
        assert_eq!(
            reference["servers"]["srv0"]["routes"][0]["match"],
            json!([
                { "asn": [64512] },
                { "remote_ip": { "ranges": ["10.0.0.0/8", "2001:db8::/32"] } },
                { "ssh": {} },
                { "http": {} },
                { "proxy_protocol": {} }
            ])
        );
    }

    #[test]
    fn asn_matcher_requires_unsigned_numbers() {
        let err = adapt("{\nlayer4 {\n0.0.0.0:443 {\n@ns asn notanumber\n}\n}\n}\n").unwrap_err();
        assert!(
            err.to_string().contains("is not an unsigned 32-bit number"),
            "{err}"
        );
    }

    #[test]
    fn undefined_matcher_reference_is_rejected() {
        let err =
            adapt("{\nlayer4 {\n0.0.0.0:443 {\nroute @missing {\nclose\n}\n}\n}\n}\n").unwrap_err();
        assert!(
            err.to_string().contains("undefined matcher `@missing`"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod t_l4_011_tests {
    //! The features T-L4-011 adds on top of the T-L4-004 TCP subset: UDP listeners, the inline
    //! `tls { client_auth { ... } }` block and the `throttle` handler.

    use super::*;

    fn app(source: &str) -> Value {
        let file = crate::parse(source).expect("parse");
        layer4_app_json(file.options.layer4.as_ref().expect("layer4 option")).expect("adapt")
    }

    #[test]
    fn adr_031_example_adapts_in_full() {
        // ADR-031's own configuration example, both listeners. A subset that cannot carry the ADR's
        // example is not the schema the ADR specifies, so this is the headline test.
        let json = app(concat!(
            "{\nlayer4 {\n",
            "0.0.0.0:443 {\n",
            "@blocked_asns asn 16509 14061\n",
            "route @blocked_asns {\nclose\n}\n",
            "@ssh tls sni ssh.example.com\n",
            "route @ssh {\ntls {\nclient_auth {\nmode require_and_verify\n",
            "trusted_ca_cert_file /etc/caddy/ssh-ca.pem\n}\n}\n",
            "proxy_protocol v2\nproxy 127.0.0.1:22\n}\n",
            "route {\nclose\n}\n}\n",
            "0.0.0.0:51820/udp {\n",
            "@wg_peer asn 12345 67890\n",
            "route @wg_peer {\nproxy 10.0.0.10:51820\n}\n",
            "route {\nclose\n}\n}\n",
            "}\n}\n"
        ));
        let tcp = &json["servers"]["srv0"];
        assert_eq!(tcp["listen"], json!(["0.0.0.0:443"]));
        assert_eq!(tcp["routes"].as_array().unwrap().len(), 3);
        assert_eq!(
            tcp["routes"][1]["handle"][0],
            json!({
                "handler": "tls",
                "client_auth": {
                    "mode": "require_and_verify",
                    "trusted_ca_cert_file": ["/etc/caddy/ssh-ca.pem"]
                }
            }),
            "the inline tls block must emit client_auth as an object"
        );
        let udp = &json["servers"]["srv1"];
        assert_eq!(udp["listen"], json!(["0.0.0.0:51820/udp"]));
        assert_eq!(
            udp["routes"][0],
            json!({
                "match": [{ "asn": [12345, 67890] }],
                "handle": [{ "handler": "proxy", "upstreams": [{ "dial": "10.0.0.10:51820" }] }]
            })
        );
    }

    #[test]
    fn inline_tls_block_defaults_mode_and_rejects_unknown_options() {
        let json = app(
            "{\nlayer4 {\n0.0.0.0:443 {\ntls {\nclient_auth {\ntrusted_ca_cert_file /a.pem\n}\n}\n}\n}\n}\n",
        );
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"][0]["client_auth"]["mode"],
            json!("require_and_verify"),
            "an omitted mode must default to require_and_verify, matching the shorthand form"
        );

        // An unknown sub-option must be located, not silently dropped: a dropped handshake
        // constraint would leave the operator believing TLS was restricted when it was not.
        let file = crate::parse("{\nlayer4 {\n0.0.0.0:443 {\ntls {\nsideways on\n}\n}\n}\n}\n")
            .expect("parse");
        let err = layer4_app_json(file.options.layer4.as_ref().unwrap()).unwrap_err();
        assert!(err.to_string().contains("sideways"), "{err}");
    }

    #[test]
    fn inline_tls_block_rejects_an_unknown_client_auth_mode() {
        let file = crate::parse(
            "{\nlayer4 {\n0.0.0.0:443 {\ntls {\nclient_auth {\nmode sometimes\n}\n}\n}\n}\n}\n",
        )
        .expect("parse");
        let err = layer4_app_json(file.options.layer4.as_ref().unwrap()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("sometimes"), "{text}");
        assert!(text.contains("require_and_verify"), "{text}");
    }

    #[test]
    fn throttle_emits_the_runtime_rate_limit_field_names() {
        // The keys must be exactly the `RateLimit` struct's fields, so the adapted JSON decodes
        // straight into the runtime handler.
        let json = app(
            "{\nlayer4 {\n0.0.0.0:443 {\nthrottle {\nupstream 10MB\ndownstream 50MiB\n}\n}\n}\n}\n",
        );
        assert_eq!(
            json["servers"]["srv0"]["routes"][0]["handle"][0],
            json!({
                "handler": "throttle",
                "upstream_bytes_per_second": 10_000_000u64,
                "downstream_bytes_per_second": 52_428_800u64,
            }),
            "SI and IEC suffixes must scale, and keys must match the runtime struct"
        );
    }

    #[test]
    fn throttle_rate_parsing_covers_the_documented_suffixes() {
        for (text, expected) in [
            ("1000", 1000u64),
            ("1KB", 1_000),
            ("1KiB", 1_024),
            ("2MB", 2_000_000),
            ("2MiB", 2_097_152),
            ("1GB", 1_000_000_000),
            ("1GiB", 1_073_741_824),
            ("10MB/s", 10_000_000),
        ] {
            let position = crate::parse("{\nlayer4 {\n0.0.0.0:443 {\nclose\n}\n}\n}\n")
                .expect("parse")
                .options
                .layer4
                .as_ref()
                .unwrap()
                .position
                .clone();
            assert_eq!(
                parse_byte_rate(text, &position).expect(text),
                expected,
                "rate `{text}`"
            );
        }
    }

    #[test]
    fn throttle_rejects_zero_and_unknown_suffixes() {
        for (source, needle) in [
            (
                "{\nlayer4 {\n0.0.0.0:443 {\nthrottle {\ndownstream 0\n}\n}\n}\n}\n",
                "greater than zero",
            ),
            (
                "{\nlayer4 {\n0.0.0.0:443 {\nthrottle {\ndownstream 5XB\n}\n}\n}\n}\n",
                "unknown suffix",
            ),
            (
                // The Caddyfile parser collapses an EMPTY block to no block at all, so
                // `throttle { }` is indistinguishable from a bare `throttle` and reports the
                // "needs a block" error rather than the "needs at least one option" one. Pinning
                // the reachable behaviour rather than the tidier unreachable branch.
                "{\nlayer4 {\n0.0.0.0:443 {\nthrottle {\n}\n}\n}\n}\n",
                "needs a block",
            ),
        ] {
            let file = crate::parse(source).expect("parse");
            let err = layer4_app_json(file.options.layer4.as_ref().unwrap()).unwrap_err();
            assert!(err.to_string().contains(needle), "{source}: {err}");
        }
    }
}
