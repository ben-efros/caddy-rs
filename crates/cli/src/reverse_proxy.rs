//! `caddy-rs reverse-proxy`: a quick, production-ready reverse proxy.
//!
//! This is the port of Caddy v2.11.9's `caddy reverse-proxy`
//! (`external/caddy/modules/caddyhttp/reverseproxy/command.go`): it parses `--from`/`--to` the
//! same way (`httpcaddyfile.ParseAddress` and `parseUpstreamDialAddress`), builds the same
//! in-memory configuration — admin disabled with `config.persist=false`, one HTTP server named
//! `proxy` listening on `:<port>`, one route with a `host` matcher when `--from` names a host and
//! a `reverse_proxy` handler — and serves it with the same runtime as `caddy-rs run`.
//!
//! Flags whose capability this build does not have are rejected before anything is started, with
//! a located error naming the flag and the missing module/feature; none of them is silently
//! ignored.
//!
//! # Supported
//!
//! * Cleartext downstreams: `http://...`, `:port`, `host:80` and the other address forms that
//!   `ParseAddress` resolves to the `http` scheme.
//! * `--to` with `host[:port]`, `http://host[:port]`, `https://host[:port]`, `unix//path` and a
//!   numeric port range (`host:8000-8005` expands to one upstream per port), repeatable and
//!   comma-separated; mixing schemes uses the first defined scheme, like stock.
//! * `--insecure` (TLS upstreams), `--access-log`, `--disable-redirects` and the default random
//!   load-balancing policy (stock emits no `load_balancing` object either).
//! * `--header-up`/`--header-down` (`"Field: value"`, repeatable), emitted as the `reverse_proxy`
//!   handler's inline `headers.request.set`/`headers.response.set`.
//! * HTTPS downstreams: the server is built exactly like stock (listen `:<port>` plus the `host`
//!   matcher when `--from` names one), so caddy-rs derives automatic HTTPS from the matcher and
//!   provisions a certificate for it — from the local CA for local/internal names, offline, and
//!   from the default ACME issuer for public names (which needs a reachable ACME server; that
//!   issuance fails closed, DIV-0001). With `--internal-certs` and a host, the explicit
//!   `apps.tls.automation.policies` entry `{subjects:[host], issuers:[{"module":"internal"}]}`
//!   that stock emits is added as well, which forces the internal issuer for any host.
//!   `--disable-redirects` keeps automatic HTTPS but sets `automatic_https.disable_redirects`
//!   (stock's `AutoHTTPS.DisableRedir`); a cleartext `--from` sets `automatic_https.disable`
//!   (stock's `AutoHTTPS.Disabled`).
//!
//! # Rejected (located errors, exit 1, before anything is bound)
//!
//! * `--from` that resolves to HTTPS but names no host (e.g. `https://:8443`): a certificate
//!   needs a name, so the listener could never complete a handshake.
//! * `--change-host-header`: it is a shortcut for `--header-up
//!   "Host: {http.reverse_proxy.upstream.hostport}"`, and this build's replacer does not implement
//!   the `http.reverse_proxy.*` namespace (DIV-0007), so the header would be written literally
//!   (or emptied) instead of naming the selected upstream.
//! * `--header-up`/`--header-down` values that contain an `http.reverse_proxy.*` placeholder, for
//!   the same reason.
//! * `--debug`: this build has no debug-level internal logging.

use std::sync::Arc;

use anyhow::{Context, Result};
use caddy_rs_core::{
    validate_config, AdminConfig, Apps, AutoHttps, AutomationPolicy, Config, GenerationStore,
    HttpApp, HttpServer, Logging, ModuleRef, ModuleRegistry, Route, ServerLogConfig, TlsApp,
    TlsAutomation,
};
use caddy_rs_server::ServerRuntime;
use serde_json::{json, Map, Value};

use crate::CliExit;

/// Caddy's default HTTP port (`caddyhttp.DefaultHTTPPort`).
const HTTP_PORT: u16 = 80;
/// Caddy's default HTTPS port (`caddyhttp.DefaultHTTPSPort`).
const HTTPS_PORT: u16 = 443;

/// Arguments for `caddy-rs reverse-proxy`, after clap parsing.
pub(crate) struct Args {
    /// `--from` / `-f` (default `localhost`).
    pub(crate) from: String,
    /// `--to` / `-t` (repeatable or comma-separated, required).
    pub(crate) to: Vec<String>,
    /// `--change-host-header` / `-c` (unsupported: placeholder namespace missing).
    pub(crate) change_host_header: bool,
    /// `--insecure` (skip TLS verification with HTTPS upstreams).
    pub(crate) insecure: bool,
    /// `--disable-redirects` / `-r`.
    pub(crate) disable_redirects: bool,
    /// `--internal-certs` / `-i`.
    pub(crate) internal_certs: bool,
    /// `--header-up` / `-H` (repeatable, `"Field: value"`).
    pub(crate) header_up: Vec<String>,
    /// `--header-down` / `-d` (repeatable, `"Field: value"`).
    pub(crate) header_down: Vec<String>,
    /// `--access-log`.
    pub(crate) access_log: bool,
    /// `--debug` / `-v` (unsupported: no debug-level internal logging).
    pub(crate) debug: bool,
}

/// A parsed downstream address (`httpcaddyfile.Address` after scheme/port inference).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FromAddress {
    scheme: String,
    host: String,
    port: u16,
}

impl FromAddress {
    /// Go's `httpcaddyfile.Address.String`: scheme, host, and the port only when it is not the
    /// scheme's default.
    fn display(&self) -> String {
        if self.host.is_empty() && self.port == 0 {
            return String::new();
        }
        let mut rendered = format!("{}://", self.scheme);
        let default_port = if self.scheme == "https" {
            HTTPS_PORT
        } else {
            HTTP_PORT
        };
        if self.port == default_port {
            rendered.push_str(&self.host);
        } else {
            rendered.push_str(&join_host_port(&self.host, self.port));
        }
        rendered
    }
}

/// One parsed upstream: its optional scheme and the dial address(es) it expands to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Upstream {
    scheme: Option<String>,
    dials: Vec<String>,
}

/// Run `caddy-rs reverse-proxy`.
pub(crate) async fn run(args: Args) -> Result<()> {
    let registry = crate::builtin_module_registry();

    if args.to.is_empty() {
        return Err(located(
            "--to",
            "required: pass at least one upstream address with --to <addr>",
        ));
    }
    let from = parse_from(&args.from).map_err(|reason| {
        located(
            &format!("--from {}", args.from),
            &format!("invalid downstream address: {reason}"),
        )
    })?;
    let mut upstreams = Vec::with_capacity(args.to.len());
    for raw in &args.to {
        upstreams.push(parse_upstream(raw).map_err(|reason| {
            located(
                &format!("--to {raw}"),
                &format!("invalid upstream address: {reason}"),
            )
        })?);
    }
    check_flags(&args, &from, &registry)?;

    let config = build_config(&args, &from, &upstreams)?;
    validate_config(&config, &registry)
        .context("the reverse-proxy configuration is not valid in this build")?;

    // Certificate and CA material is written under the data directory; resolve it the way `run`
    // does so `$CADDY_RS_DATA_DIR` and Caddy's data path are honoured (`reverse-proxy` has no
    // `--data-dir` flag, and the generated configuration declares no `storage.root`).
    let data_dir = caddy_rs_core::data_dir::resolve_server_data_dir(None, None);
    for warning in &data_dir.warnings {
        eprintln!("caddy-rs: warning: {warning}");
    }

    let store = Arc::new(GenerationStore::new(Arc::new(registry)));
    store
        .load(config)
        .context("cannot activate the reverse-proxy configuration")?;
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_data_root(data_dir.path)
        .without_socket_activation();
    runtime
        .apply()
        .await
        .context("cannot start the reverse-proxy listener")?;

    let dials: Vec<String> = upstreams
        .iter()
        .flat_map(|upstream| upstream.dials.iter().cloned())
        .collect();
    // Stock logs this through `caddy.Log().Info` after `caddy.Run` succeeds:
    // `caddy proxying` with `from` (the filled-out downstream address) and `to` (every upstream
    // dial address) fields.
    eprintln!(
        "caddy proxying from={} to=[{}]",
        from.display(),
        dials.join(" ")
    );
    if dials.len() > 1 {
        eprintln!("using default load balancing policy random");
    }

    let channels = crate::signals::shutdown_channels()?;
    runtime
        .run_with_force(channels.shutdown, channels.force)
        .await
        .context("reverse-proxy failed")?;
    Ok(())
}

/// Reject every flag or value whose capability this build does not have, before anything starts.
///
/// Stock returns `caddy.ExitCodeFailedStartup` (1) for a startup failure; every rejection here
/// uses the same code. All checks run before the generation store is loaded, so a rejected flag
/// can never leave a listener behind.
fn check_flags(args: &Args, from: &FromAddress, registry: &ModuleRegistry) -> Result<()> {
    if args.debug {
        return Err(located(
            "--debug",
            "caddy-rs has no debug-level internal logging; re-run without --debug",
        ));
    }
    if args.change_host_header {
        return Err(located(
            "--change-host-header",
            "this flag is a shortcut for --header-up \"Host: \
             {http.reverse_proxy.upstream.hostport}\", and this build's replacer does not \
             implement the http.reverse_proxy.* placeholder namespace (DIV-0007), so the upstream \
             Host header could not name the selected upstream; re-run without \
             --change-host-header",
        ));
    }
    for (flag, values) in [
        ("--header-up", &args.header_up),
        ("--header-down", &args.header_down),
    ] {
        for (index, value) in values.iter().enumerate() {
            parse_header(value).map_err(|reason| {
                located(
                    &format!("{flag} {index}"),
                    &format!("invalid format \"{value}\" (expecting \"Field: value\"): {reason}"),
                )
            })?;
            if value.contains("{http.reverse_proxy.") {
                return Err(located(
                    &format!("{flag} {index}"),
                    "this build's replacer does not implement the http.reverse_proxy.* \
                     placeholder namespace (DIV-0007), so the value would not expand to the \
                     selected upstream; re-run with a literal value",
                ));
            }
        }
    }
    // Stock's HTTPS path is driven by the host matcher (implicit automatic HTTPS), so the only
    // address shape it cannot serve is an HTTPS listener with nothing to issue a certificate for.
    if from.scheme == "https" && from.host.is_empty() {
        return Err(located(
            "--from",
            &format!(
                "{} resolves to HTTPS but names no host, so there is no certificate subject to \
                 issue for; give a host in --from",
                from.display()
            ),
        ));
    }
    if !registry.contains("http.handlers.reverse_proxy") {
        return Err(located(
            "reverse_proxy",
            "module `http.handlers.reverse_proxy` is not compiled into this build",
        ));
    }
    Ok(())
}

/// A located error naming the flag (or capability) and what is missing.
fn located(location: &str, reason: &str) -> anyhow::Error {
    CliExit {
        code: 1,
        message: format!("{location}: {reason}"),
    }
    .into()
}

/// Parse `--from` exactly like `httpcaddyfile.ParseAddress` plus stock's scheme/port inference.
///
/// A path is rejected (`paths are not allowed`), a scheme other than `http`/`https` is rejected,
/// and the inferred scheme follows stock: with no scheme, an explicit port 80 or an empty host
/// means HTTP, anything else means HTTPS; an empty port becomes 80 for HTTP and 443 for HTTPS.
fn parse_from(raw: &str) -> std::result::Result<FromAddress, String> {
    let trimmed = raw.trim();
    let (scheme, remaining) = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return Err(format!(
                    "unsupported scheme `{scheme}` (only http and https are supported)"
                ));
            }
            (Some(scheme), rest)
        }
        None => (None, trimmed),
    };
    let (host_port, path) = match remaining.find('/') {
        Some(index) => (&remaining[..index], Some(&remaining[index..])),
        None => (remaining, None),
    };
    if let Some(path) = path {
        if !path.is_empty() {
            return Err(format!("paths are not allowed: {path}"));
        }
    }
    let (host, port) = split_host_port(host_port)?;
    let port_number = match port.as_deref() {
        Some(port) if !port.is_empty() => Some(
            port.parse::<u16>()
                .map_err(|_| format!("invalid port `{port}`"))?,
        ),
        _ => None,
    };
    let scheme = match scheme {
        Some(scheme) => scheme,
        None => {
            if port_number == Some(HTTP_PORT) || host.is_empty() {
                "http".to_string()
            } else {
                "https".to_string()
            }
        }
    };
    let port = match port_number {
        Some(port) => port,
        None if scheme == "https" => HTTPS_PORT,
        None => HTTP_PORT,
    };
    Ok(FromAddress { scheme, host, port })
}

/// Parse one `--to` value like `parseUpstreamDialAddress`, expanding a port range.
fn parse_upstream(raw: &str) -> std::result::Result<Upstream, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("address is empty".to_string());
    }

    // Unix-socket networks keep their dial string verbatim (`unix//run/caddy.sock`).
    if let Some(rest) = trimmed.strip_prefix("unix/") {
        if rest.is_empty() || rest == "/" {
            return Err("unix upstream address has no socket path".to_string());
        }
        return Ok(Upstream {
            scheme: None,
            dials: vec![format!("unix/{rest}")],
        });
    }
    if trimmed.starts_with("fd/") {
        return Err(
            "file-descriptor upstream networks (`fd/`) are not supported by this build".to_string(),
        );
    }

    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "unsupported scheme `{scheme}` (only http and https are supported)"
            ));
        }
        if rest.contains('{') {
            return Err(
                "placeholders are not allowed when an upstream address contains a scheme"
                    .to_string(),
            );
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(
                "URLs for proxy upstreams only support scheme, host, and port components"
                    .to_string(),
            );
        }
        let (host, port) = split_host_port(rest)?;
        if host.is_empty() {
            return Err("upstream URL has no host".to_string());
        }
        let port = match port.as_deref() {
            Some(port) if !port.is_empty() => port.to_string(),
            _ => {
                if scheme == "https" {
                    "443".to_string()
                } else {
                    "80".to_string()
                }
            }
        };
        if scheme == "http" && port == "443" {
            return Err(
                "upstream address has conflicting scheme (http://) and port (:443, the HTTPS \
                 port)"
                    .to_string(),
            );
        }
        if scheme == "https" && port == "80" {
            return Err(
                "upstream address has conflicting scheme (https://) and port (:80, the HTTP \
                 port)"
                    .to_string(),
            );
        }
        let dials = expand_ports(&host, &port)?;
        return Ok(Upstream {
            scheme: Some(scheme),
            dials,
        });
    }

    let (host, port) = split_host_port(trimmed)?;
    if host.is_empty() {
        return Err("upstream address has no host".to_string());
    }
    // Stock assumes port 80 when only a hostname is given.
    let port = match port.as_deref() {
        Some(port) if !port.is_empty() => port.to_string(),
        _ => "80".to_string(),
    };
    let dials = expand_ports(&host, &port)?;
    Ok(Upstream {
        scheme: None,
        dials,
    })
}

/// Split `host[:port]` (bracketed IPv6 allowed). An absent port is `None`.
fn split_host_port(value: &str) -> std::result::Result<(String, Option<String>), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("invalid address `{value}`: missing `]`"));
        };
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port.to_string()),
            None if after.is_empty() => None,
            None => return Err(format!("invalid address `{value}`: unexpected `{after}`")),
        };
        return Ok((host.to_string(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return Err(format!(
                "invalid address `{value}`: IPv6 addresses must be enclosed in brackets"
            ));
        }
        return Ok((host.to_string(), Some(port.to_string())));
    }
    Ok((value.to_string(), None))
}

/// Expand a single port or a `start-end` range into one dial address per port.
fn expand_ports(host: &str, port: &str) -> std::result::Result<Vec<String>, String> {
    let (start, end) = match port.split_once('-') {
        Some((start, end)) => {
            if end.contains('-') {
                return Err(format!("port range invalid: {port}"));
            }
            let start = start
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{start}`"))?;
            let end = end
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{end}`"))?;
            if start > end {
                return Err(format!("port range invalid: {port}"));
            }
            (start, end)
        }
        None => {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{port}`"))?;
            (port, port)
        }
    };
    Ok((start..=end)
        .map(|port| join_host_port(host, port))
        .collect())
}

/// Format a host/port pair like Go's `net.JoinHostPort`.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parse one `"Field: value"` header argument, mirroring stock's `strings.Cut` validation.
fn parse_header(value: &str) -> std::result::Result<(String, String), String> {
    let Some((field, value)) = value.split_once(':') else {
        return Err("expected \"Field: value\"".to_string());
    };
    let (field, value) = (field.trim(), value.trim());
    if field.is_empty() || value.is_empty() {
        return Err("both the field name and the value must be non-empty".to_string());
    }
    Ok((field.to_string(), value.to_string()))
}

/// Build the in-memory configuration `reverse-proxy` runs.
///
/// Mirrors stock: admin disabled with `config.persist=false`; one `proxy` server listening on
/// `:<port>`; one route whose `host` matcher is present when `--from` names a host; a
/// `reverse_proxy` handler with the expanded upstreams, an `http` transport (with TLS when the
/// upstream scheme is `https`), and the request/response header operations; automatic HTTPS
/// disabled for cleartext downstreams and redirects disabled with `--disable-redirects`; the
/// access log when requested; and, with `--internal-certs` and a host, the explicit internal-CA
/// automation policy stock emits.
fn build_config(args: &Args, from: &FromAddress, upstreams: &[Upstream]) -> Result<Config> {
    let mut handler = Map::new();
    handler.insert("handler".to_string(), Value::String("reverse_proxy".into()));
    let dials: Vec<Value> = upstreams
        .iter()
        .flat_map(|upstream| upstream.dials.iter())
        .map(|dial| json!({ "dial": dial }))
        .collect();
    handler.insert("upstreams".to_string(), Value::Array(dials));

    // Stock always emits the HTTP transport (`caddyconfig.JSONModuleObject(ht, "protocol",
    // "http", nil)`); TLS is enabled by the presence of the `tls` object, and `--insecure` only
    // matters for HTTPS upstreams.
    let to_scheme = upstreams
        .iter()
        .find_map(|upstream| upstream.scheme.clone());
    let mut transport = Map::new();
    transport.insert("protocol".to_string(), Value::String("http".into()));
    if to_scheme.as_deref() == Some("https") {
        transport.insert(
            "tls".to_string(),
            if args.insecure {
                json!({ "insecure_skip_verify": true })
            } else {
                json!({})
            },
        );
    }
    handler.insert("transport".to_string(), Value::Object(transport));

    let request_headers: Map<String, Value> = args
        .header_up
        .iter()
        .map(|value| parse_header(value))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .map(|(field, value)| (field, json!([value])))
        .collect();
    let response_headers: Map<String, Value> = args
        .header_down
        .iter()
        .map(|value| parse_header(value))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .map(|(field, value)| (field, json!([value])))
        .collect();
    if !request_headers.is_empty() || !response_headers.is_empty() {
        let mut headers = Map::new();
        if !request_headers.is_empty() {
            headers.insert("request".to_string(), json!({ "set": request_headers }));
        }
        if !response_headers.is_empty() {
            headers.insert("response".to_string(), json!({ "set": response_headers }));
        }
        handler.insert("headers".to_string(), Value::Object(headers));
    }

    let mut route = Route {
        handle: vec![Value::Object(handler)],
        ..Default::default()
    };
    if !from.host.is_empty() {
        route.matcher_sets = vec![json!({ "host": [from.host.clone()] })];
    }

    let automatic_https = if from.scheme == "http" {
        Some(AutoHttps {
            disable: true,
            ..Default::default()
        })
    } else if args.disable_redirects {
        Some(AutoHttps {
            disable_redirects: true,
            ..Default::default()
        })
    } else {
        None
    };

    let mut server = HttpServer {
        listen: vec![format!(":{}", from.port)],
        routes: vec![route],
        automatic_https,
        ..Default::default()
    };
    if args.access_log {
        server.logs = Some(ServerLogConfig::default());
    }

    let mut http_servers = std::collections::BTreeMap::new();
    http_servers.insert("proxy".to_string(), server);

    // Caddy disables the admin endpoint and config persistence for `reverse-proxy`.
    let mut admin_extra = std::collections::BTreeMap::new();
    admin_extra.insert("config".to_string(), json!({ "persist": false }));

    // Stock emits an explicit internal-CA policy only for `--internal-certs` with a host.
    let tls = if args.internal_certs && !from.host.is_empty() {
        Some(TlsApp {
            automation: Some(TlsAutomation {
                policies: vec![AutomationPolicy {
                    subjects: vec![from.host.clone()],
                    issuers: vec![ModuleRef {
                        module: Some("internal".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        })
    } else {
        None
    };

    Ok(Config {
        admin: Some(AdminConfig {
            disabled: true,
            extra: admin_extra,
            ..Default::default()
        }),
        // Access logging in this build is emitted only for configurations that contain a
        // `logging` section; stock's default logger always exists, so add it when requested.
        logging: args.access_log.then(Logging::default),
        apps: Some(Apps {
            http: Some(HttpApp {
                servers: http_servers,
                ..Default::default()
            }),
            tls,
            pki: None,
            extra: std::collections::BTreeMap::new(),
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_inference_matches_stock() {
        assert_eq!(
            parse_from("localhost").expect("parse"),
            FromAddress {
                scheme: "https".into(),
                host: "localhost".into(),
                port: 443
            }
        );
        assert_eq!(
            parse_from("localhost:8080").expect("parse"),
            FromAddress {
                scheme: "https".into(),
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(
            parse_from("localhost:80").expect("parse"),
            FromAddress {
                scheme: "http".into(),
                host: "localhost".into(),
                port: 80
            }
        );
        assert_eq!(
            parse_from(":8080").expect("parse"),
            FromAddress {
                scheme: "http".into(),
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(
            parse_from("http://localhost:8080").expect("parse"),
            FromAddress {
                scheme: "http".into(),
                host: "localhost".into(),
                port: 8080
            }
        );
        assert!(parse_from("http://localhost/path").is_err());
        assert!(parse_from("ftp://localhost").is_err());
        assert!(parse_from("localhost:notaport").is_err());
    }

    #[test]
    fn upstream_parsing_matches_stock() {
        assert_eq!(
            parse_upstream("localhost").expect("parse"),
            Upstream {
                scheme: None,
                dials: vec!["localhost:80".into()]
            }
        );
        assert_eq!(
            parse_upstream("https://example.com").expect("parse"),
            Upstream {
                scheme: Some("https".into()),
                dials: vec!["example.com:443".into()]
            }
        );
        assert_eq!(
            parse_upstream("127.0.0.1:8000-8002").expect("parse"),
            Upstream {
                scheme: None,
                dials: vec![
                    "127.0.0.1:8000".into(),
                    "127.0.0.1:8001".into(),
                    "127.0.0.1:8002".into()
                ]
            }
        );
        assert_eq!(
            parse_upstream("unix//run/caddy.sock").expect("parse"),
            Upstream {
                scheme: None,
                dials: vec!["unix//run/caddy.sock".into()]
            }
        );
        assert!(parse_upstream("ftp://example.com").is_err());
        assert!(parse_upstream("http://example.com:443").is_err());
        assert!(parse_upstream("https://example.com:80").is_err());
        assert!(parse_upstream("http://example.com/path").is_err());
        assert!(parse_upstream("example.com:70000").is_err());
        assert!(parse_upstream("example.com:9000-8000").is_err());
    }

    #[test]
    fn header_arguments_require_field_and_value() {
        assert_eq!(
            parse_header("X-Test: yes").expect("parse"),
            ("X-Test".to_string(), "yes".to_string())
        );
        assert!(parse_header("X-Test").is_err());
        assert!(parse_header(": value").is_err());
        assert!(parse_header("X-Test: ").is_err());
    }
}
