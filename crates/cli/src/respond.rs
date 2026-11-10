//! `caddy-rs respond`: a fixed-response HTTP server for development and testing.
//!
//! This is the port of Caddy v2.11.9's `cmdRespond`
//! (`external/caddy/modules/caddyhttp/staticresp.go`): it builds a one-route HTTP app whose route
//! is a `static_response` handler and serves it with the same server runtime as `caddy-rs run`.
//!
//! Flag and argument semantics follow Caddy exactly, including the rule that a final unnamed
//! numeric argument is a status code only when it is a 3-digit number and `--status` does not
//! appear literally in `argv` (Caddy inspects `os.Args`, so `--status=404` does not count and the
//! shorthand `-s` does not count either). Reproducing that rule keeps scripts that rely on either
//! spelling behaving exactly as they do with Caddy.
//!
//! Supported: `--listen` (TCP host/port, optional port range, and absolute Unix socket paths),
//! `--status`, `--body`, repeated `--header`, `--access-log`, the positional `<body|status>` and a
//! body piped on stdin. A body may use Caddy's three template variables (`{{.N}}`, `{{.Port}}`,
//! `{{.Address}}`); any other template construct is rejected with a located error instead of being
//! served literally.
//!
//! Not supported: `--debug`, because this build has no debug-level internal logging. The flag is
//! rejected with a located error naming it rather than being silently ignored.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use caddy_rs_core::{
    AdminConfig, Apps, AutoHttps, Config, GenerationStore, HttpApp, HttpServer, Logging, Route,
    ServerLogConfig,
};
use caddy_rs_server::ServerRuntime;
use serde_json::{Map, Value};

use crate::CliExit;

/// Arguments for `caddy-rs respond`, after clap parsing.
pub(crate) struct Args {
    /// `--listen` / `-l` value (default `:0`).
    pub(crate) listen: String,
    /// `--status` / `-s` value (default 200).
    pub(crate) status: i64,
    /// `--body` / `-b` value (default empty).
    pub(crate) body: String,
    /// `--access-log`.
    pub(crate) access_log: bool,
    /// `--debug` / `-v`.
    pub(crate) debug: bool,
    /// Repeated `--header` / `-H` values.
    pub(crate) headers: Vec<String>,
    /// Positional `<body|status>` arguments; Caddy accepts at most one.
    pub(crate) arguments: Vec<String>,
}

/// Where the response body came from, for located error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyOrigin {
    Flag,
    Argument,
    Stdin,
}

/// One configured HTTP server: the listen string, plus the template values Caddy would pass to
/// `buildHTTPServer` for that server.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerSpec {
    configured: String,
    n: usize,
    port: u16,
    address: String,
}

/// The network family of a parsed `--listen` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenNetwork {
    Tcp,
    Unix,
}

/// A parsed `--listen` value (Caddy's `ParseNetworkAddress`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenSpec {
    network: ListenNetwork,
    host: String,
    start_port: u16,
    end_port: u16,
    unix_path: Option<String>,
    raw: String,
}

/// Run `caddy-rs respond`.
pub(crate) async fn run(args: Args) -> Result<()> {
    if args.debug {
        return Err(CliExit {
            code: 1,
            message: "--debug is not supported by this build: caddy-rs has no debug-level \
                      internal logging; re-run without --debug"
                .to_string(),
        }
        .into());
    }
    if args.arguments.len() > 1 {
        return Err(CliExit {
            code: 1,
            message: "too many unflagged arguments".to_string(),
        }
        .into());
    }

    // Caddy's `statusCodeFlagSpecified` is `slices.Contains(os.Args, "--status")`, not "the flag
    // parser saw --status": reproduce that literal check (see the module docs).
    let status_flag_specified = std::env::args().any(|argument| argument == "--status");
    let argument = args
        .arguments
        .first()
        .map(String::as_str)
        .unwrap_or_default();

    let (status, body, origin) =
        select_response(args.status, &args.body, argument, status_flag_specified)?;
    let status = validate_status(status)?;
    let headers = parse_headers(&args.headers)?;
    let listen = parse_listen(&args.listen)?;
    let servers = listen.servers();
    let config = build_config(&servers, status, &headers, &body, origin, args.access_log)?;

    let store = Arc::new(GenerationStore::new(Arc::new(
        crate::builtin_module_registry(),
    )));
    store
        .load(config)
        .context("cannot activate the respond configuration")?;
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let status = runtime
        .apply()
        .await
        .context("cannot start the respond server")?;

    for server in &servers {
        let bound = status.listener_address(&server.configured).ok_or_else(|| {
            anyhow!(
                "listener `{}` was configured but did not bind",
                server.configured
            )
        })?;
        println!("Server address: {bound}");
    }

    let channels = crate::signals::shutdown_channels()?;
    runtime
        .run_with_force(channels.shutdown, channels.force)
        .await
        .context("respond server failed")?;
    Ok(())
}

/// Apply Caddy's status/body selection rules to the flags and the unnamed argument.
///
/// Mirrors `cmdRespond` line for line, including the `strconv.Atoi` branch: a numeric argument
/// that is not a 3-digit code is *ignored* (it is not used as a body), and an argument that is
/// numeric while `--status` was specified becomes the body.
fn select_response(
    status_flag: i64,
    body_flag: &str,
    argument: &str,
    status_flag_specified: bool,
) -> Result<(i64, String, Option<BodyOrigin>)> {
    let mut status = status_flag;
    let mut body = body_flag.to_string();
    let mut origin = if body.is_empty() {
        None
    } else {
        Some(BodyOrigin::Flag)
    };

    if !argument.is_empty() {
        // Specifying both --body and --status makes the unnamed argument redundant.
        if !body_flag.is_empty() && status_flag_specified {
            return Err(CliExit {
                code: 1,
                message: format!("unflagged argument \"{argument}\" is overridden by flags"),
            }
            .into());
        }
        match argument.parse::<i64>() {
            Ok(value) if !status_flag_specified => {
                if (100..=999).contains(&value) {
                    status = value;
                }
            }
            _ => {
                if body.is_empty() {
                    body = argument.to_string();
                    origin = Some(BodyOrigin::Argument);
                }
            }
        }
    }

    // If we still need a body, read it from stdin when it is a pipe (Caddy's ModeNamedPipe test;
    // a regular-file redirect is deliberately not read, matching Caddy).
    if body.is_empty() && stdin_is_pipe() {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("cannot read the response body from stdin")?;
        body = String::from_utf8(bytes).map_err(|_| CliExit {
            code: 1,
            message: "the response body read from stdin is not valid UTF-8".to_string(),
        })?;
        origin = Some(BodyOrigin::Stdin);
    }

    Ok((status, body, origin))
}

/// Whether stdin is a pipe (Caddy reads a body only from `os.ModeNamedPipe`).
#[cfg(unix)]
fn stdin_is_pipe() -> bool {
    use std::os::unix::io::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` initializes the buffer it is given on success; the fd is stdin, which is
    // valid for the lifetime of the call.
    let result = unsafe { libc::fstat(std::io::stdin().as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return false;
    }
    // SAFETY: `result == 0` means `fstat` filled the buffer.
    let stat = unsafe { stat.assume_init() };
    (stat.st_mode & libc::S_IFMT) == libc::S_IFIFO
}

#[cfg(not(unix))]
fn stdin_is_pipe() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Validate the status code the same way Caddy's `static_response` handler ultimately does.
///
/// Caddy accepts any `int` here and Go panics per request for a code outside 100-999; rejecting at
/// startup with a located error naming `--status` is this build's documented, fail-loud behaviour.
fn validate_status(status: i64) -> Result<u16> {
    if (100..=999).contains(&status) {
        if let Ok(code) = http::StatusCode::from_u16(status as u16) {
            return Ok(code.as_u16());
        }
    }
    Err(CliExit {
        code: 1,
        message: format!("--status: {status} is not a valid HTTP status code (expected 100-999)"),
    }
    .into())
}

/// Parse repeated `--header "Field: value"` values into Caddy's `http.Header` shape.
///
/// `http.Header.Set` semantics: the field name is canonicalized and a repeated field replaces the
/// earlier value, so the map keeps one value per case-insensitive name.
fn parse_headers(raw: &[String]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut headers = BTreeMap::new();
    for (index, header) in raw.iter().enumerate() {
        let Some((key, value)) = header.split_once(':') else {
            return Err(header_format_error(index, header));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(header_format_error(index, header));
        }
        let name: http::HeaderName = key.parse().map_err(|_| CliExit {
            code: 1,
            message: format!("header {index}: invalid header name \"{key}\""),
        })?;
        headers.insert(name.as_str().to_string(), vec![value.to_string()]);
    }
    Ok(headers)
}

fn header_format_error(index: usize, header: &str) -> anyhow::Error {
    CliExit {
        code: 1,
        message: format!(
            "header {index}: invalid format \"{header}\" (expecting \"Field: value\")"
        ),
    }
    .into()
}

/// Parse a Caddy listen address (`[network/]host[:port[-end]]`).
///
/// caddy-rs supports the TCP and Unix-socket forms `respond` uses. UDP, `fd/` socket activation and
/// Unix permission suffixes are capabilities this build does not have for this command, so they
/// are rejected with a located error naming `--listen`.
fn parse_listen(input: &str) -> Result<ListenSpec> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(listen_error(input, "address is empty"));
    }

    let (network, address) = match trimmed.split_once('/') {
        Some((prefix, rest)) => (prefix.trim().to_ascii_lowercase(), rest),
        None => ("tcp".to_string(), trimmed),
    };

    match network.as_str() {
        "" | "tcp" => {
            let (host, port) =
                split_host_port(address).map_err(|reason| listen_error(input, &reason))?;
            let (start_port, end_port) =
                parse_port_range(&port).map_err(|reason| listen_error(input, &reason))?;
            Ok(ListenSpec {
                network: ListenNetwork::Tcp,
                host,
                start_port,
                end_port,
                unix_path: None,
                raw: input.to_string(),
            })
        }
        "unix" => {
            if !address.starts_with('/') {
                return Err(listen_error(input, "unix socket path must be absolute"));
            }
            if address.contains('|') {
                return Err(listen_error(
                    input,
                    "unix socket permission bits are not supported by this build",
                ));
            }
            if address.contains('\0') {
                return Err(listen_error(input, "unix socket path contains a NUL byte"));
            }
            Ok(ListenSpec {
                network: ListenNetwork::Unix,
                host: String::new(),
                start_port: 0,
                end_port: 0,
                unix_path: Some(address.to_string()),
                raw: input.to_string(),
            })
        }
        "udp" => Err(listen_error(
            input,
            "UDP listeners are not supported by respond (it serves plain HTTP/1.1)",
        )),
        "fd" => Err(listen_error(
            input,
            "fd/socket-activation listeners are not supported by this build",
        )),
        other => Err(listen_error(
            input,
            &format!("unsupported network `{other}`"),
        )),
    }
}

fn listen_error(input: &str, reason: &str) -> anyhow::Error {
    CliExit {
        code: 1,
        message: format!("--listen \"{input}\": {reason}"),
    }
    .into()
}

/// Split a TCP address into host and port, accepting an omitted port like Caddy's
/// `SplitNetworkAddress` (an omitted port becomes `0`).
fn split_host_port(address: &str) -> std::result::Result<(String, String), String> {
    if address.is_empty() {
        return Err("address is empty".to_string());
    }
    if let Some(rest) = address.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err("unterminated IPv6 literal".to_string());
        };
        if after.is_empty() {
            return Ok((host.to_string(), String::new()));
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err("expected `:port` after the IPv6 literal".to_string());
        };
        return Ok((host.to_string(), port.to_string()));
    }
    if let Some((host, port)) = address.rsplit_once(':') {
        if host.contains(':') {
            return Err(
                "expected `host:port` (IPv6 literals must be bracketed, e.g. `[::1]:443`)"
                    .to_string(),
            );
        }
        return Ok((host.to_string(), port.to_string()));
    }
    Ok((address.to_string(), String::new()))
}

/// Parse Caddy's inclusive port range (`8000` or `8000-8005`); an empty port means `0`.
fn parse_port_range(port: &str) -> std::result::Result<(u16, u16), String> {
    if port.is_empty() {
        return Ok((0, 0));
    }
    let (start, end) = match port.split_once('-') {
        Some((start, end)) => (start, end),
        None => (port, port),
    };
    let start: u16 = start
        .parse()
        .map_err(|_| format!("invalid start port `{start}`"))?;
    let end: u16 = end
        .parse()
        .map_err(|_| format!("invalid end port `{end}`"))?;
    if end < start {
        return Err("end port must not be less than start port".to_string());
    }
    Ok((start, end))
}

impl ListenSpec {
    /// Expand the spec into one server per port, with Caddy's template values.
    fn servers(&self) -> Vec<ServerSpec> {
        match self.network {
            ListenNetwork::Unix => vec![ServerSpec {
                configured: format!("unix/{}", self.unix_path.as_deref().unwrap_or_default()),
                n: 0,
                port: 0,
                address: self.raw.clone(),
            }],
            ListenNetwork::Tcp => (self.start_port..=self.end_port)
                .enumerate()
                .map(|(offset, port)| {
                    let configured = tcp_address(&self.host, port);
                    ServerSpec {
                        configured: configured.clone(),
                        n: offset,
                        port,
                        address: configured,
                    }
                })
                .collect(),
        }
    }
}

/// Format a host/port pair like Go's `net.JoinHostPort`.
fn tcp_address(host: &str, port: u16) -> String {
    if host.is_empty() {
        format!(":{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Build the in-memory configuration `respond` runs: admin disabled, one `static_response` route
/// per server, and (with `--access-log`) Caddy's default stderr logging plus a per-server `logs`
/// association.
fn build_config(
    servers: &[ServerSpec],
    status: u16,
    headers: &BTreeMap<String, Vec<String>>,
    body_template: &str,
    body_origin: Option<BodyOrigin>,
    access_log: bool,
) -> Result<Config> {
    let mut http_servers = BTreeMap::new();
    for (index, server) in servers.iter().enumerate() {
        let body = evaluate_template(body_template, body_origin, server)?;
        let mut handler = Map::new();
        handler.insert(
            "handler".to_string(),
            Value::String("static_response".into()),
        );
        handler.insert("status_code".to_string(), Value::from(status));
        handler.insert("body".to_string(), Value::String(body));
        if !headers.is_empty() {
            handler.insert(
                "headers".to_string(),
                serde_json::to_value(headers).context("cannot encode response headers")?,
            );
        }
        let route = Route {
            handle: vec![Value::Object(handler)],
            ..Default::default()
        };
        let mut http_server = HttpServer {
            listen: vec![server.configured.clone()],
            routes: vec![route],
            // Caddy sets `DisableRedir: true` for `respond`; this build never redirects a
            // plain-HTTP `respond` listener.
            automatic_https: Some(AutoHttps {
                disable_redirects: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        if access_log {
            http_server.logs = Some(ServerLogConfig::default());
        }
        http_servers.insert(format!("static{index}"), http_server);
    }

    // Caddy disables the admin endpoint and config persistence for `respond`.
    let mut admin_extra = BTreeMap::new();
    admin_extra.insert(
        "config".to_string(),
        serde_json::json!({ "persist": false }),
    );

    Ok(Config {
        admin: Some(AdminConfig {
            disabled: true,
            extra: admin_extra,
            ..Default::default()
        }),
        logging: access_log.then(Logging::default),
        apps: Some(Apps {
            http: Some(HttpApp {
                servers: http_servers,
                ..Default::default()
            }),
            tls: None,
            pki: None,
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    })
}

/// Evaluate Caddy's `respond` body template.
///
/// Caddy uses Go's `text/template`; this build supports exactly the three documented variables and
/// rejects every other construct with a located error naming where the body came from.
fn evaluate_template(
    body: &str,
    origin: Option<BodyOrigin>,
    server: &ServerSpec,
) -> Result<String> {
    let mut output = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(template_error(origin, &rest[start..]));
        };
        let expression = after[..end].trim();
        match expression {
            ".N" => output.push_str(&server.n.to_string()),
            ".Port" => output.push_str(&server.port.to_string()),
            ".Address" => output.push_str(&server.address),
            _ => return Err(template_error(origin, &rest[start..start + 2 + end + 2])),
        }
        rest = &after[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

fn template_error(origin: Option<BodyOrigin>, expression: &str) -> anyhow::Error {
    let source = match origin {
        Some(BodyOrigin::Flag) => "--body",
        Some(BodyOrigin::Argument) => "the unflagged argument",
        Some(BodyOrigin::Stdin) => "the stdin body",
        None => "the body",
    };
    CliExit {
        code: 1,
        message: format!(
            "{source}: unsupported template expression `{expression}`; respond supports only \
             `{{{{.N}}}}`, `{{{{.Port}}}}` and `{{{{.Address}}}}`"
        ),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_spec(input: &str) -> ListenSpec {
        parse_listen(input).expect("listen parses")
    }

    #[test]
    fn listen_accepts_caddy_tcp_forms() {
        assert_eq!(
            tcp_spec(":0").servers(),
            vec![ServerSpec {
                configured: ":0".into(),
                n: 0,
                port: 0,
                address: ":0".into()
            }]
        );
        assert_eq!(tcp_spec("127.0.0.1").servers()[0].configured, "127.0.0.1:0");
        assert_eq!(tcp_spec("[::1]:8080").servers()[0].configured, "[::1]:8080");
        assert_eq!(
            tcp_spec("localhost:8080").servers()[0].configured,
            "localhost:8080"
        );
    }

    #[test]
    fn listen_expands_port_ranges_with_template_values() {
        let servers = tcp_spec("127.0.0.1:8000-8002").servers();
        assert_eq!(servers.len(), 3);
        assert_eq!(
            servers[1],
            ServerSpec {
                configured: "127.0.0.1:8001".into(),
                n: 1,
                port: 8001,
                address: "127.0.0.1:8001".into()
            }
        );
        assert_eq!(servers[2].n, 2);
    }

    #[test]
    fn listen_accepts_absolute_unix_sockets() {
        let spec = tcp_spec("unix//tmp/caddy-respond.sock");
        assert_eq!(spec.network, ListenNetwork::Unix);
        let servers = spec.servers();
        assert_eq!(servers[0].configured, "unix//tmp/caddy-respond.sock");
        assert_eq!(servers[0].address, "unix//tmp/caddy-respond.sock");
        assert_eq!(servers[0].port, 0);
    }

    #[test]
    fn listen_rejects_unsupported_and_malformed_forms() {
        for (input, needle) in [
            ("udp/:0", "UDP listeners"),
            ("fd/3", "socket-activation"),
            ("unix/relative.sock", "absolute"),
            ("unix//tmp/x.sock|0666", "permission bits"),
            ("127.0.0.1:8000-7999", "end port"),
            ("127.0.0.1:not-a-port", "invalid start port"),
            ("::1:8080", "bracketed"),
            ("", "address is empty"),
        ] {
            let error = parse_listen(input).expect_err(input);
            let message = format!("{error:#}");
            assert!(
                message.contains("--listen") && message.contains(needle),
                "input {input:?}: {message}"
            );
        }
    }

    #[test]
    fn response_selection_matches_caddy() {
        // No argument: the flag values win.
        assert_eq!(
            select_response(201, "hi", "", false).unwrap(),
            (201, "hi".to_string(), Some(BodyOrigin::Flag))
        );
        // A 3-digit numeric argument is the status when --status is absent.
        assert_eq!(
            select_response(200, "", "404", false).unwrap(),
            (404, String::new(), None)
        );
        // A non-numeric argument is the body.
        assert_eq!(
            select_response(200, "", "hello", false).unwrap(),
            (200, "hello".to_string(), Some(BodyOrigin::Argument))
        );
        // A numeric non-3-digit argument is ignored, exactly like Caddy's Atoi branch.
        assert_eq!(
            select_response(200, "", "99", false).unwrap(),
            (200, String::new(), None)
        );
        // --status plus a numeric argument: the argument becomes the body.
        assert_eq!(
            select_response(201, "", "404", true).unwrap(),
            (201, "404".to_string(), Some(BodyOrigin::Argument))
        );
        // --status=404 is not the literal `--status`, so Caddy treats the argument as the status.
        assert_eq!(
            select_response(404, "", "200", false).unwrap(),
            (200, String::new(), None)
        );
        // Body and status flags together make the argument redundant.
        let error = select_response(201, "x", "y", true).expect_err("override must fail");
        assert!(
            format!("{error:#}").contains("unflagged argument \"y\" is overridden by flags"),
            "{error:#}"
        );
    }

    #[test]
    fn headers_follow_set_semantics_and_report_bad_input() {
        let headers = parse_headers(&[
            "X-Test: yes".into(),
            "x-test: replaced".into(),
            "Content-Type: application/json".into(),
        ])
        .unwrap();
        assert_eq!(headers["x-test"], vec!["replaced".to_string()]);
        assert_eq!(
            headers["content-type"],
            vec!["application/json".to_string()]
        );

        for (raw, needle) in [
            ("X-Bad", "header 0: invalid format \"X-Bad\""),
            ("X-Empty: ", "invalid format"),
            ("   : value", "invalid format"),
            ("bad header: value", "invalid header name"),
        ] {
            let error = parse_headers(&[raw.to_string()]).expect_err(raw);
            assert!(format!("{error:#}").contains(needle), "{raw:?}: {error:#}");
        }
    }

    #[test]
    fn status_codes_outside_go_http_range_are_rejected_by_name() {
        assert_eq!(validate_status(200).unwrap(), 200);
        assert_eq!(validate_status(600).unwrap(), 600);
        for status in [0, 99, 1000, -1] {
            let error = validate_status(status).expect_err("invalid status");
            assert!(
                format!("{error:#}").contains("--status"),
                "{status}: {error:#}"
            );
        }
    }

    #[test]
    fn templates_expand_only_the_documented_variables() {
        let server = ServerSpec {
            configured: "127.0.0.1:8080".into(),
            n: 3,
            port: 8080,
            address: "127.0.0.1:8080".into(),
        };
        assert_eq!(
            evaluate_template(
                "n={{.N}} port={{ .Port }} addr={{.Address}}",
                Some(BodyOrigin::Flag),
                &server
            )
            .unwrap(),
            "n=3 port=8080 addr=127.0.0.1:8080"
        );
        assert_eq!(evaluate_template("plain", None, &server).unwrap(), "plain");

        for (template, needle) in [
            ("{{.Foo}}", "unsupported template expression"),
            ("{{if .N}}", "unsupported template expression"),
            ("{{.N", "unsupported template expression"),
        ] {
            let error = evaluate_template(template, Some(BodyOrigin::Argument), &server)
                .expect_err(template);
            let message = format!("{error:#}");
            assert!(
                message.contains("the unflagged argument") && message.contains(needle),
                "{template:?}: {message}"
            );
        }
    }

    #[test]
    fn config_matches_caddy_respond_shape() {
        let servers = tcp_spec("127.0.0.1:0").servers();
        let mut headers = BTreeMap::new();
        headers.insert("x-test".to_string(), vec!["yes".to_string()]);
        let config = build_config(&servers, 201, &headers, "hello", None, true).unwrap();
        let value = config.to_value().unwrap();
        assert_eq!(value["admin"]["disabled"], true);
        assert_eq!(value["admin"]["config"]["persist"], false);
        assert!(value["logging"].is_object());
        let server = &value["apps"]["http"]["servers"]["static0"];
        assert_eq!(server["listen"][0], "127.0.0.1:0");
        assert_eq!(server["logs"], serde_json::json!({}));
        assert_eq!(
            server["routes"][0]["handle"][0],
            serde_json::json!({
                "handler": "static_response",
                "status_code": 201,
                "body": "hello",
                "headers": {"x-test": ["yes"]},
            })
        );
    }
}
