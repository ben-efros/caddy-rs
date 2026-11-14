//! Configuration validation.
//!
//! Validation is the gate between "decoded JSON" and "provisionable configuration generation".
//! It walks every handler and matcher reference, so an unsupported module fails at validation
//! time with a located error instead of at request time. It also enforces the structural
//! invariants this implementation relies on: unique route ids, unique listeners, and well-formed
//! reverse-proxy upstreams. Constructs Caddy accepts but this build does not implement are
//! rejected with [`Error::Unsupported`] and a tracking task, never silently accepted.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::config::{
    AutomationPolicy, BaseLog, CertificateAuthority, CertificatesConfig, Config, HttpApp,
    HttpServer, ListenerWrapperConfig, Logging, ModuleRef, PinSource, Pkcs11CertConfig, PkiApp,
    PkiKeyPair, ProxyProtocolConfig, Route, ServerLogConfig, StorageConfig, TlsApp, TlsAutomation,
};
use crate::duration::parse_caddy_duration_json;
use crate::error::{Error, Result};
use crate::listen::{ListenAddr, Network};
use crate::module::{ModuleKind, ModuleRegistry};

/// Counts produced by a successful validation walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// HTTP servers inspected.
    pub servers: usize,
    /// Routes inspected, including nested subroutes.
    pub routes: usize,
    /// Handler modules inspected.
    pub handlers: usize,
    /// Matcher modules inspected.
    pub matchers: usize,
    /// TLS automation policies inspected.
    pub tls_policies: usize,
}

/// Validate a configuration against a module registry.
pub fn validate_config(config: &Config, registry: &ModuleRegistry) -> Result<ValidationReport> {
    let mut validator = Validator {
        registry,
        ids: BTreeSet::new(),
        pki_ca_ids: None,
        report: ValidationReport::default(),
    };

    if !config.extra.is_empty() {
        let fields: Vec<&str> = config.extra.keys().map(String::as_str).collect();
        return Err(Error::invalid(
            "",
            format!(
                "unknown top-level configuration field(s): {}",
                fields.join(", ")
            ),
        ));
    }

    if let Some(admin) = &config.admin {
        if let Some(listen) = &admin.listen {
            validate_admin_listen(listen)?;
        }
    }

    if let Some(logging) = &config.logging {
        validate_logging(logging, registry)?;
    }

    if let Some(storage) = &config.storage {
        validate_storage(storage, registry, "storage")?;
    }

    match &config.apps {
        None => {}
        Some(apps) => {
            if !apps.extra.is_empty() {
                let apps_unknown: Vec<&str> = apps.extra.keys().map(String::as_str).collect();
                return Err(Error::invalid(
                    "apps",
                    format!(
                        "unknown app module(s): {}; this build supports `http`, `tls` and `pki`",
                        apps_unknown.join(", ")
                    ),
                ));
            }
            // Validate PKI before TLS: internal issuers reference CA IDs that the PKI app defines.
            if let Some(pki) = &apps.pki {
                validator.pki(pki)?;
            }
            if let Some(http) = &apps.http {
                validator.http(http)?;
            }
            if let Some(tls) = &apps.tls {
                validator.tls(tls)?;
            }
        }
    }

    Ok(validator.report)
}

/// Longest Unix domain socket path, in bytes, that fits in `sockaddr_un.sun_path`.
///
/// `sun_path` is 108 bytes on Linux, but the kernel also requires the terminating NUL to fit, so
/// at most 107 bytes of path can bind; a 108-byte path is rejected by `bind(2)` with `EINVAL`
/// (errno 22), verified against real sockets. This uses that 107-byte bound. The BSDs use a
/// smaller array (104 bytes); a path accepted here can still be too long there, so the admin
/// listener reports the platform error at bind time.
pub const UNIX_SOCKET_PATH_MAX: usize = 107;

/// Validate the `admin.listen` address, applying the Unix socket rules to `unix/...` values.
///
/// `unix//run/caddy-admin.sock` denotes the absolute path `/run/caddy-admin.sock` (the first
/// slash separates the network from the address); `unix/run/caddy-admin.sock` denotes a
/// relative path and is rejected.
fn validate_admin_listen(listen: &str) -> Result<()> {
    let address = ListenAddr::parse_at(listen, "admin.listen")?;
    if address.network == Network::Unix {
        validate_unix_socket_path(&address.address, "admin.listen")?;
    }
    Ok(())
}

/// Validate a Unix domain socket path against the rules the admin endpoint needs to bind.
///
/// The path must be absolute, must contain no null byte, must fit in the OS `sockaddr_un` limit
/// ([`UNIX_SOCKET_PATH_MAX`]), and its parent directory must exist and be writable. Writability
/// is read from the parent's permission bits rather than probed with a write, so the verdict does
/// not depend on the uid running validation (root can bind inside a `0555` directory).
///
/// Failures are located at `located` (for example `admin.listen`) and name both the rule and the
/// offending value.
pub fn validate_unix_socket_path(path: &str, located: impl Into<String>) -> Result<()> {
    let located = located.into();
    let invalid = |reason: String| Error::InvalidListen {
        value: path.to_string(),
        path: located.clone(),
        reason,
    };

    if path.contains('\0') {
        return Err(invalid(
            "unix socket path must not contain a null byte".to_string(),
        ));
    }
    if !path.starts_with('/') {
        return Err(invalid("unix socket path must be absolute".to_string()));
    }
    let length = path.len();
    if length > UNIX_SOCKET_PATH_MAX {
        return Err(invalid(format!(
            "unix socket path is {length} bytes, exceeding the {UNIX_SOCKET_PATH_MAX}-byte \
             `sockaddr_un` limit"
        )));
    }

    let parent = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("/"));
    let metadata = std::fs::metadata(parent).map_err(|error| {
        invalid(format!(
            "parent directory `{}` does not exist or is not accessible: {error}",
            parent.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "parent `{}` is not a directory",
            parent.display()
        )));
    }
    if metadata.permissions().readonly() {
        return Err(invalid(format!(
            "parent directory `{}` is not writable",
            parent.display()
        )));
    }
    Ok(())
}

/// Validate one server's `listener_wrappers` list.
///
/// Wrapper modules must be registered (only `proxy_protocol` and the implicit `tls` marker are
/// implemented in this build), `proxy_protocol` options must decode into the typed configuration
/// with valid CIDR ranges, and the Caddy ordering rules for the `tls` marker are enforced (it may
/// not be first and may only appear once).
fn validate_listener_wrappers(
    wrappers: &[ListenerWrapperConfig],
    base: &str,
    registry: &ModuleRegistry,
) -> Result<()> {
    let mut seen_tls = false;
    for (index, wrapper) in wrappers.iter().enumerate() {
        let path = format!("{base}[{index}]");
        let name = wrapper.wrapper.as_deref().ok_or_else(|| {
            Error::invalid(
                format!("{path}.wrapper"),
                "listener wrapper object must name a `wrapper`",
            )
        })?;
        let module = registry.resolve_listener_wrapper(name).ok_or_else(|| {
            registry.unknown_module(
                ModuleKind::ListenerWrapper,
                name.to_string(),
                format!("{path}.wrapper"),
            )
        })?;
        if module.json_key == "proxy_protocol" {
            let options: ProxyProtocolConfig =
                serde_json::from_value(Value::Object(wrapper.extra.clone().into_iter().collect()))
                    .map_err(|error| {
                        Error::invalid(&path, format!("invalid proxy_protocol options: {error}"))
                    })?;
            for (cidr_index, cidr) in options.allow.iter().enumerate() {
                validate_cidr(cidr, &format!("{path}.allow[{cidr_index}]"))?;
            }
            for (cidr_index, cidr) in options.deny.iter().enumerate() {
                validate_cidr(cidr, &format!("{path}.deny[{cidr_index}]"))?;
            }
        } else if module.json_key == "tls" {
            if index == 0 {
                return Err(Error::invalid(
                    format!("{path}.wrapper"),
                    "the `tls` listener wrapper must not be first: wrappers listed before it run \
                     before the TLS handshake",
                ));
            }
            if seen_tls {
                return Err(Error::invalid(
                    format!("{path}.wrapper"),
                    "the `tls` listener wrapper may only be specified once",
                ));
            }
            seen_tls = true;
        }
    }
    Ok(())
}

/// Validate a CIDR range such as `10.0.0.0/8` or `2001:db8::/32`.
fn validate_cidr(value: &str, path: &str) -> Result<()> {
    use std::net::IpAddr;

    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address: IpAddr = address.parse().map_err(|_| {
        Error::invalid(
            path,
            format!("`{value}` is not a valid IP address or CIDR range"),
        )
    })?;
    if let Some(prefix) = prefix {
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| Error::invalid(path, format!("`{value}` has an invalid prefix length")))?;
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(Error::invalid(
                path,
                format!("`{value}` prefix length must be at most {max}"),
            ));
        }
    }
    Ok(())
}

/// Validate Caddy `caddy.Duration` and numeric HTTP server limit fields at load time.
///
/// The core model preserves the timeout fields as JSON so the server crate can parse both Caddy
/// spellings; this pass parses the same values during validation so malformed durations or
/// non-integer limits fail `validate`/`load` with a located error instead of only failing apply
/// (DIV-0039 residual). Caddy's own JSON decoding accepts negative durations (server provisioning
/// treats non-positive as disabled) and the extra `d` day unit, so those remain valid here.
fn validate_server_limits(server: &HttpServer, path: &str) -> Result<()> {
    if let Some(protocols) = &server.protocols {
        if protocols.is_empty() {
            return Err(Error::invalid(
                format!("{path}.protocols"),
                "`protocols` must not be empty when present".to_string(),
            ));
        }
        for protocol in protocols {
            match protocol.as_str() {
                "h1" | "h2" | "h2c" => {}
                // Caddy accepts h3. A build without the `http3` feature must reject it loudly
                // rather than accept a configuration it cannot serve (HTTP/3 is never silently
                // downgraded to TCP).
                "h3" => {
                    #[cfg(not(feature = "http3"))]
                    {
                        return Err(Error::invalid(
                            format!("{path}.protocols"),
                            "HTTP/3 support is not compiled in; rebuild with the `http3` feature or \
                             remove `h3` from `protocols`"
                                .to_string(),
                        ));
                    }
                }
                other => {
                    return Err(Error::invalid(
                        format!("{path}.protocols"),
                        format!("unsupported HTTP protocol `{other}`; expected h1, h2, h2c or h3"),
                    ))
                }
            }
        }
    }
    // Typed Caddy `caddy.Duration` fields.
    for (field, value) in [
        ("read_timeout", server.read_timeout.as_ref()),
        ("write_timeout", server.write_timeout.as_ref()),
        ("idle_timeout", server.idle_timeout.as_ref()),
    ] {
        if let Some(value) = value {
            validate_duration_field(value, &format!("{path}.{field}"))?;
        }
    }

    // Caddy timeout fields preserved in the unknown-field map (not typed in the core model yet).
    for field in [
        "read_header_timeout",
        "read_idle_timeout",
        "write_idle_timeout",
        "keepalive_interval",
        "keepalive_idle",
    ] {
        if let Some(value) = server.extra.get(field) {
            validate_duration_field(value, &format!("{path}.{field}"))?;
        }
    }

    // Numeric limits. Caddy-native `max_header_bytes`/`keepalive_count` must be integers; the
    // caddy-rs extension caps are non-negative integers (DIV-0036), matching the server parser.
    if let Some(value) = server.extra.get("max_header_bytes") {
        validate_non_negative_integer(
            value,
            &format!("{path}.max_header_bytes"),
            "number of bytes",
        )?;
    }
    if let Some(value) = server.extra.get("max_request_body_size") {
        validate_non_negative_integer(
            value,
            &format!("{path}.max_request_body_size"),
            "number of bytes",
        )?;
    }
    if let Some(value) = server.extra.get("max_connections") {
        validate_non_negative_integer(
            value,
            &format!("{path}.max_connections"),
            "connection count",
        )?;
    }
    if let Some(value) = server.extra.get("keepalive_count") {
        if value.as_i64().is_none() && value.as_u64().is_none() {
            return Err(Error::invalid(
                format!("{path}.keepalive_count"),
                format!("`keepalive_count` must be an integer, got {value}"),
            ));
        }
    }
    // caddy-rs extension: server identity (T-CONF-060). A non-string or empty value is a located
    // error, matching the server parser so `validate`/`load` fail instead of only apply.
    if let Some(value) = server.extra.get("server_identity") {
        crate::identity::ServerIdentity::from_config_value(
            value,
            &format!("{path}.server_identity"),
        )?;
    }
    Ok(())
}

fn validate_duration_field(value: &Value, path: &str) -> Result<()> {
    parse_caddy_duration_json(value)
        .map_err(|message| Error::invalid(path, format!("invalid duration: {message}")))?;
    Ok(())
}

fn validate_non_negative_integer(value: &Value, path: &str, unit: &str) -> Result<()> {
    if value.as_u64().is_none() {
        return Err(Error::invalid(
            path,
            format!("must be a non-negative integer {unit}, got {value}"),
        ));
    }
    Ok(())
}

/// Validate one server's access-log association (`apps.http.servers.*.logs`).
///
/// Caddy itself performs no structural validation here; caddy-rs rejects host patterns that can
/// never match a portless host (empty, whitespace/control characters) with a located error, so a
/// typo cannot silently disable access logging for a site.
fn validate_server_logs(logs: &ServerLogConfig, path: &str) -> Result<()> {
    if let Some(name) = &logs.default_logger_name {
        validate_logger_name(name, &format!("{path}.default_logger_name"))?;
    }
    for (host, names) in &logs.logger_names {
        validate_log_host(host, &format!("{path}.logger_names[{host:?}]"))?;
        for (index, name) in names.as_slice().iter().enumerate() {
            validate_logger_name(name, &format!("{path}.logger_names[{host:?}][{index}]"))?;
        }
    }
    for (index, host) in logs.skip_hosts.iter().enumerate() {
        validate_log_host(host, &format!("{path}.skip_hosts[{index}]"))?;
    }
    Ok(())
}

/// A host pattern for `logger_names`/`skip_hosts`: a non-empty hostname without a port, optionally
/// with `*` labels.
fn validate_log_host(host: &str, path: &str) -> Result<()> {
    if host.trim().is_empty() {
        return Err(Error::invalid(path, "host pattern must not be empty"));
    }
    if host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::invalid(
            path,
            format!("host pattern `{host}` must not contain whitespace or control characters"),
        ));
    }
    Ok(())
}

/// A zap logger name component. Empty is valid (it selects the base access logger).
fn validate_logger_name(name: &str, path: &str) -> Result<()> {
    if name
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::invalid(
            path,
            format!("logger name `{name}` must not contain whitespace or control characters"),
        ));
    }
    Ok(())
}

/// Validate the `logging` section: every configured writer, encoder and core must be a module this
/// build knows. Unknown fields are preserved by the model; Caddy ignores unknown JSON fields here,
/// so validation only checks module references and required module names.
fn validate_logging(logging: &Logging, registry: &ModuleRegistry) -> Result<()> {
    if let Some(sink) = &logging.sink {
        validate_base_log(&sink.base, registry, "logging.sink")?;
    }
    for (name, log) in &logging.logs {
        validate_base_log(&log.base, registry, &format!("logging.logs.{name}"))?;
    }
    Ok(())
}

fn validate_base_log(base: &BaseLog, registry: &ModuleRegistry, path: &str) -> Result<()> {
    if let Some(writer) = &base.writer {
        let writer_path = format!("{path}.writer.output");
        let name = require_module_name(
            writer.output.as_deref(),
            &writer_path,
            "log writer",
            "output",
        )?;
        if registry.resolve_log_writer(name).is_none() {
            return Err(registry.unknown_module(
                ModuleKind::LogWriter,
                name.to_string(),
                writer_path,
            ));
        }
    }
    if let Some(encoder) = &base.encoder {
        let encoder_path = format!("{path}.encoder.format");
        let name = require_module_name(
            encoder.format.as_deref(),
            &encoder_path,
            "log encoder",
            "format",
        )?;
        if registry.resolve_log_encoder(name).is_none() {
            return Err(registry.unknown_module(
                ModuleKind::LogEncoder,
                name.to_string(),
                encoder_path,
            ));
        }
    }
    if let Some(core) = &base.core {
        let core_path = format!("{path}.core.module");
        let name = require_module_name(core.module.as_deref(), &core_path, "log core", "module")?;
        if registry.resolve_log_core(name).is_none() {
            return Err(registry.unknown_module(ModuleKind::LogCore, name.to_string(), core_path));
        }
    }
    Ok(())
}

/// A module object must name its module; absent names get a located error rather than a serde error
/// so the message points at the exact JSON path.
fn require_module_name<'a>(
    value: Option<&'a str>,
    path: &str,
    kind: &str,
    field: &str,
) -> Result<&'a str> {
    value.ok_or_else(|| {
        Error::invalid(
            path,
            format!("{kind} object must name a module with field `{field}`"),
        )
    })
}

fn validate_storage(storage: &StorageConfig, registry: &ModuleRegistry, path: &str) -> Result<()> {
    let module_path = format!("{path}.module");
    let module = storage
        .module
        .as_deref()
        .ok_or_else(|| Error::invalid(&module_path, "storage object must name a `module`"))?;
    if registry.get_by_key(ModuleKind::Storage, module).is_none() {
        return Err(registry.unknown_module(ModuleKind::Storage, module.to_string(), module_path));
    }
    Ok(())
}

struct Validator<'a> {
    registry: &'a ModuleRegistry,
    ids: BTreeSet<String>,
    /// CA IDs from `apps.pki`; `None` means the implicit default `local` CA is available.
    pki_ca_ids: Option<BTreeSet<String>>,
    report: ValidationReport,
}

impl Validator<'_> {
    fn http(&mut self, http: &HttpApp) -> Result<()> {
        if !http.extra.is_empty() {
            let fields: Vec<&str> = http.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid(
                "apps.http",
                format!("unknown HTTP app field(s): {}", fields.join(", ")),
            ));
        }

        if let Some(metrics) = &http.metrics {
            if !metrics.extra.is_empty() {
                let fields: Vec<&str> = metrics.extra.keys().map(String::as_str).collect();
                return Err(Error::invalid(
                    "apps.http.metrics",
                    format!(
                        "unknown experimental metrics field(s): {} (Caddy v2.11.9 accepts \
                         `per_host`, `observe_catchall_hosts` and `otlp`)",
                        fields.join(", ")
                    ),
                ));
            }
            if let Some((field, tracking_id)) = metrics.unsupported_field() {
                return Err(Error::unsupported(
                    format!("apps.http.metrics.{field}"),
                    "experimental HTTP metrics option",
                    tracking_id,
                ));
            }
        }

        let mut listeners: BTreeMap<&str, &str> = BTreeMap::new();
        for (server_name, server) in &http.servers {
            let server_path = format!("apps.http.servers.{server_name}");
            if server.listen.is_empty() {
                return Err(Error::invalid(
                    format!("{server_path}.listen"),
                    "server must declare at least one listen address",
                ));
            }
            for (index, listen) in server.listen.iter().enumerate() {
                let path = format!("{server_path}.listen[{index}]");
                let parsed = ListenAddr::parse_at(listen, path.clone())?;
                if parsed.network == crate::Network::Udp {
                    #[cfg(not(feature = "http3"))]
                    {
                        return Err(Error::invalid(
                            path.clone(),
                            format!(
                                "HTTP/3 support is not compiled in; the UDP listener `{listen}` \
                                 cannot be served (rebuild with the `http3` feature or remove the \
                                 `udp/...` listener)"
                            ),
                        ));
                    }
                    #[cfg(feature = "http3")]
                    {
                        // HTTP/3 is served over QUIC: a UDP listener needs both explicit h3 and
                        // TLS, otherwise the socket would silently drop every QUIC packet.
                        let offers_h3 = match server.protocols.as_ref() {
                            None => true,
                            Some(protocols) => protocols.iter().any(|protocol| protocol == "h3"),
                        };
                        if !offers_h3 {
                            return Err(Error::invalid(
                                path.clone(),
                                "a UDP listener requires `protocols` to include `h3` (HTTP/3); \
                                 configured protocols do not offer it"
                                    .to_string(),
                            ));
                        }
                        let https_port = http.https_port.unwrap_or(443);
                        let has_policies = server
                            .tls_connection_policies
                            .as_ref()
                            .is_some_and(|policies| !policies.is_empty());
                        if !(has_policies || parsed.port() == Some(https_port)) {
                            return Err(Error::invalid(
                                path.clone(),
                                format!(
                                    "a UDP listener requires TLS (port {https_port} or \
                                     `tls_connection_policies`); HTTP/3 is never served cleartext"
                                ),
                            ));
                        }
                    }
                }
                if let Some(previous) = listeners.insert(listen.as_str(), server_name) {
                    return Err(Error::invalid(
                        format!("{server_path}.listen[{index}]"),
                        format!(
                            "duplicate listener `{listen}`: already used by server `{previous}`"
                        ),
                    ));
                }
            }
            if let Some(automatic_https) = &server.automatic_https {
                if !automatic_https.extra.is_empty() {
                    let fields: Vec<&str> =
                        automatic_https.extra.keys().map(String::as_str).collect();
                    return Err(Error::invalid(
                        format!("{server_path}.automatic_https"),
                        format!("unknown automatic_https field(s): {}", fields.join(", ")),
                    ));
                }
            }
            if let Some(logs) = &server.logs {
                validate_server_logs(logs, &format!("{server_path}.logs"))?;
            }
            validate_listener_wrappers(
                &server.listener_wrappers,
                &format!("{server_path}.listener_wrappers"),
                self.registry,
            )?;
            validate_server_limits(server, &server_path)?;
            self.routes(&server.routes, &format!("{server_path}.routes"))?;
            if let Some(errors) = &server.errors {
                if !errors.extra.is_empty() {
                    let fields: Vec<&str> = errors.extra.keys().map(String::as_str).collect();
                    return Err(Error::invalid(
                        format!("{server_path}.errors"),
                        format!("unknown errors field(s): {}", fields.join(", ")),
                    ));
                }
                self.routes(&errors.routes, &format!("{server_path}.errors.routes"))?;
            }
            self.report.servers += 1;
        }
        Ok(())
    }

    fn routes(&mut self, routes: &[Route], base: &str) -> Result<()> {
        for (index, route) in routes.iter().enumerate() {
            let route_path = format!("{base}[{index}]");
            if let Some(id) = &route.id {
                if id.trim().is_empty() {
                    return Err(Error::invalid(
                        format!("{route_path}.@id"),
                        "route id must not be empty",
                    ));
                }
                if !self.ids.insert(id.clone()) {
                    return Err(Error::invalid(
                        format!("{route_path}.@id"),
                        format!("duplicate route id `{id}`"),
                    ));
                }
            }
            for (handler_index, handler) in route.handle.iter().enumerate() {
                self.handler(handler, &format!("{route_path}.handle[{handler_index}]"))?;
            }
            for (set_index, set) in route.matcher_sets.iter().enumerate() {
                self.matcher_set(set, &format!("{route_path}.match[{set_index}]"))?;
            }
            self.report.routes += 1;
        }
        Ok(())
    }

    fn handler(&mut self, value: &Value, path: &str) -> Result<()> {
        let object = value.as_object().ok_or_else(|| {
            Error::invalid(path, "handler must be a JSON object with a `handler` key")
        })?;
        let name = object
            .get("handler")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::invalid(path, "handler object is missing string field `handler`")
            })?;
        let module = self.registry.resolve_handler(name).ok_or_else(|| {
            self.registry.unknown_module(
                ModuleKind::HttpHandler,
                name.to_string(),
                format!("{path}.handler"),
            )
        })?;
        self.report.handlers += 1;

        match module.json_key {
            "subroute" => match object.get("routes") {
                // Caddy's `subroute.routes` is optional (`json:"routes,omitempty"`); a subroute
                // with no routes is valid and behaves as a no-op that passes control on.
                None | Some(Value::Null) => {}
                Some(Value::Array(nested)) => {
                    let decoded: Vec<Route> = serde_json::from_value(Value::Array(nested.clone()))
                        .map_err(|source| {
                            Error::invalid(
                                format!("{path}.routes"),
                                format!("cannot decode nested routes: {source}"),
                            )
                        })?;
                    self.routes(&decoded, &format!("{path}.routes"))?;
                }
                Some(_) => {
                    return Err(Error::invalid(
                        format!("{path}.routes"),
                        "subroute handler field `routes` must be an array of routes",
                    ))
                }
            },
            "reverse_proxy" => {
                // Caddy supports dynamically discovered upstreams (`dynamic_upstreams` with
                // `source`, `refresh`, `grace_period`, ...); the proxy runtime implements the
                // `srv`/`a`/`multi` sources (T-PROXY-036), so the construct is accepted here and
                // the source-specific options are validated at provisioning time. `upstreams`
                // becomes optional when a dynamic source is configured, as in Caddy.
                let has_dynamic = object.get("dynamic_upstreams").is_some();
                if has_dynamic {
                    if let Some(dynamic) = object.get("dynamic_upstreams") {
                        if !dynamic.is_object() && !dynamic.is_array() {
                            return Err(Error::invalid(
                                format!("{path}.dynamic_upstreams"),
                                "reverse_proxy `dynamic_upstreams` must be an object or array",
                            ));
                        }
                    }
                }
                let empty_upstreams: Vec<Value> = Vec::new();
                let upstreams = match object.get("upstreams").and_then(Value::as_array) {
                    Some(upstreams) => upstreams,
                    None if has_dynamic => &empty_upstreams,
                    None => {
                        return Err(Error::invalid(
                            format!("{path}.upstreams"),
                            "reverse_proxy requires an array field `upstreams`",
                        ))
                    }
                };
                if upstreams.is_empty() && !has_dynamic {
                    return Err(Error::invalid(
                        format!("{path}.upstreams"),
                        "reverse_proxy requires at least one upstream",
                    ));
                }
                for (index, upstream) in upstreams.iter().enumerate() {
                    let upstream_path = format!("{path}.upstreams[{index}]");
                    let upstream_object = upstream.as_object().ok_or_else(|| {
                        Error::invalid(&upstream_path, "upstream must be a JSON object")
                    })?;
                    match upstream_object.get("dial").and_then(Value::as_str) {
                        Some(dial) if !dial.trim().is_empty() => {}
                        _ => {
                            return Err(Error::invalid(
                                format!("{upstream_path}.dial"),
                                "upstream must declare a non-empty string `dial`",
                            ))
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn matcher_set(&mut self, value: &Value, path: &str) -> Result<()> {
        let object = value
            .as_object()
            .ok_or_else(|| Error::invalid(path, "matcher set must be a JSON object"))?;
        if object.is_empty() {
            return Ok(());
        }
        for (key, matcher) in object {
            if key == "not" {
                let nested = matcher.as_array().ok_or_else(|| {
                    Error::invalid(
                        format!("{path}.not"),
                        "`not` must be an array of matcher sets",
                    )
                })?;
                for (index, set) in nested.iter().enumerate() {
                    self.matcher_set(set, &format!("{path}.not[{index}]"))?;
                }
                continue;
            }
            if self.registry.resolve_matcher(key).is_none() {
                return Err(self.registry.unknown_module(
                    ModuleKind::HttpMatcher,
                    key.clone(),
                    format!("{path}.{key}"),
                ));
            }
            self.report.matchers += 1;
        }
        Ok(())
    }

    fn pki(&mut self, pki: &PkiApp) -> Result<()> {
        if !pki.extra.is_empty() {
            let fields: Vec<&str> = pki.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid(
                "apps.pki",
                format!("unknown PKI app field(s): {}", fields.join(", ")),
            ));
        }
        let Some(authorities) = &pki.certificate_authorities else {
            return Ok(());
        };
        let mut ids = BTreeSet::new();
        for (id, authority) in authorities {
            self.certificate_authority(id, authority)?;
            ids.insert(id.clone());
        }
        // An empty `certificate_authorities` map behaves like an absent app: Caddy provisions the
        // default `local` CA implicitly, so the set stays `None` in that case.
        self.pki_ca_ids = if ids.is_empty() { None } else { Some(ids) };
        Ok(())
    }

    fn certificate_authority(&self, id: &str, authority: &CertificateAuthority) -> Result<()> {
        let path = format!("apps.pki.certificate_authorities.{id}");
        if id.trim().is_empty() {
            return Err(Error::invalid(
                &path,
                "certificate authority ID must not be empty (use `local` for the default CA)",
            ));
        }
        if let Some(declared) = &authority.id {
            if declared != id {
                return Err(Error::invalid(
                    format!("{path}.id"),
                    format!(
                        "certificate authority `id` field `{declared}` does not match its certificate_authorities key `{id}`"
                    ),
                ));
            }
        }
        if !authority.extra.is_empty() {
            let fields: Vec<&str> = authority.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid(
                &path,
                format!(
                    "unknown certificate authority field(s): {}",
                    fields.join(", ")
                ),
            ));
        }
        for (field, value) in [
            ("intermediate_lifetime", authority.intermediate_lifetime),
            ("maintenance_interval", authority.maintenance_interval),
        ] {
            if let Some(value) = value {
                if value <= 0 {
                    return Err(Error::invalid(
                        format!("{path}.{field}"),
                        format!("`{field}` must be a positive duration in nanoseconds"),
                    ));
                }
            }
        }
        if let Some(ratio) = authority.renewal_window_ratio {
            if !ratio.is_finite() || ratio <= 0.0 || ratio > 1.0 {
                return Err(Error::invalid(
                    format!("{path}.renewal_window_ratio"),
                    format!("`renewal_window_ratio` must be a number in (0, 1], got {ratio}"),
                ));
            }
        }
        if let Some(root) = &authority.root {
            self.pki_key_pair(root, &format!("{path}.root"))?;
        }
        if let Some(intermediate) = &authority.intermediate {
            self.pki_key_pair(intermediate, &format!("{path}.intermediate"))?;
        }
        if let Some(storage) = &authority.storage {
            validate_storage(storage, self.registry, &format!("{path}.storage"))?;
        }
        Ok(())
    }

    fn pki_key_pair(&self, pair: &PkiKeyPair, path: &str) -> Result<()> {
        if !pair.extra.is_empty() {
            let fields: Vec<&str> = pair.extra.keys().map(String::as_str).collect();
            return Err(Error::invalid(
                path,
                format!("unknown key-pair field(s): {}", fields.join(", ")),
            ));
        }
        for (field, value) in [
            ("certificate", &pair.certificate),
            ("private_key", &pair.private_key),
        ] {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(Error::invalid(
                        format!("{path}.{field}"),
                        format!("`{field}` must not be empty"),
                    ));
                }
            }
        }
        if let Some(format) = &pair.format {
            if format != "pem_file" {
                return Err(Error::invalid(
                    format!("{path}.format"),
                    format!("unsupported key-pair format `{format}`; only `pem_file` is supported"),
                ));
            }
        }
        Ok(())
    }

    fn tls(&mut self, tls: &TlsApp) -> Result<()> {
        if let Some(certificates) = &tls.certificates {
            self.certificates(certificates, "apps.tls.certificates")?;
        }
        if let Some(automation) = &tls.automation {
            self.automation(automation)?;
        }
        if let Some(session_tickets) = &tls.session_tickets {
            if let Some(key_source) = &session_tickets.key_source {
                let path = "apps.tls.session_tickets.key_source.provider";
                let provider = require_module_name(
                    key_source.provider.as_deref(),
                    path,
                    "session ticket key provider",
                    "provider",
                )?;
                if self
                    .registry
                    .get_by_key(ModuleKind::StekProvider, provider)
                    .is_none()
                {
                    return Err(self.registry.unknown_module(
                        ModuleKind::StekProvider,
                        provider.to_string(),
                        path.to_string(),
                    ));
                }
            }
        }
        if let Some(dns) = &tls.dns {
            let path = "apps.tls.dns.name";
            let name = require_module_name(dns.name.as_deref(), path, "DNS provider", "name")?;
            if self
                .registry
                .get_by_key(ModuleKind::DnsProvider, name)
                .is_none()
            {
                return Err(self.registry.unknown_module(
                    ModuleKind::DnsProvider,
                    name.to_string(),
                    path.to_string(),
                ));
            }
        }
        Ok(())
    }

    fn certificates(&mut self, certificates: &CertificatesConfig, path: &str) -> Result<()> {
        if certificates.load_files.is_some() {
            self.certificate_loader("load_files", &format!("{path}.load_files"))?;
        }
        if certificates.load_pem.is_some() {
            self.certificate_loader("load_pem", &format!("{path}.load_pem"))?;
        }
        if certificates.automate.is_some() {
            self.certificate_loader("automate", &format!("{path}.automate"))?;
        }
        if let Some(entries) = &certificates.pkcs11 {
            self.certificate_loader("pkcs11", &format!("{path}.pkcs11"))?;
            for (index, entry) in entries.iter().enumerate() {
                self.pkcs11_entry(entry, &format!("{path}.pkcs11[{index}]"))?;
            }
        }
        // Remaining keys are other certificate-loader modules (load_folders, load_storage, and any
        // future loader); the model preserves them, validation resolves them.
        for key in certificates.extra.keys() {
            self.certificate_loader(key, &format!("{path}.{key}"))?;
        }
        Ok(())
    }

    /// Validate one `tls.certificates.pkcs11[i]` entry.
    ///
    /// `token`/`slot`, `key_label`/`key_id`, and `certificate`/`certificate_pem` are mutually
    /// exclusive pairs. PIN source and value must match: `env` needs `pin`, `file` needs
    /// `pin_file`. PIN values never appear in error messages.
    fn pkcs11_entry(&self, entry: &Pkcs11CertConfig, path: &str) -> Result<()> {
        // Exactly one of token / slot.
        match (entry.token.is_some(), entry.slot.is_some()) {
            (true, true) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "token and slot are mutually exclusive; configure only one".into(),
                });
            }
            (false, false) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "one of token or slot is required".into(),
                });
            }
            _ => {}
        }
        // Exactly one of key_label / key_id.
        match (entry.key_label.is_some(), entry.key_id.is_some()) {
            (true, true) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "key_label and key_id are mutually exclusive; configure only one"
                        .into(),
                });
            }
            (false, false) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "one of key_label or key_id is required".into(),
                });
            }
            _ => {}
        }
        // Exactly one of certificate / certificate_pem.
        match (entry.certificate.is_some(), entry.certificate_pem.is_some()) {
            (true, true) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message:
                        "certificate and certificate_pem are mutually exclusive; configure only one"
                            .into(),
                });
            }
            (false, false) => {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "one of certificate or certificate_pem is required".into(),
                });
            }
            _ => {}
        }
        // PIN source must be consistent with the PIN value fields.
        match entry.pin_source {
            PinSource::Env => {
                if entry.pin.is_none() {
                    return Err(Error::Invalid {
                        path: path.to_string(),
                        message: "pin_source=env requires pin".into(),
                    });
                }
                if entry.pin_file.is_some() {
                    return Err(Error::Invalid {
                        path: path.to_string(),
                        message: "pin_source=env cannot be combined with pin_file".into(),
                    });
                }
            }
            PinSource::File => {
                if entry.pin_file.is_none() {
                    return Err(Error::Invalid {
                        path: path.to_string(),
                        message: "pin_source=file requires pin_file".into(),
                    });
                }
                if entry.pin.is_some() {
                    return Err(Error::Invalid {
                        path: path.to_string(),
                        message: "pin_source=file cannot be combined with pin".into(),
                    });
                }
            }
        }
        // Hex-validate key_id if present.
        if let Some(key_id) = &entry.key_id {
            if key_id.len() % 2 != 0 || key_id.bytes().any(|b| !b.is_ascii_hexdigit()) {
                return Err(Error::Invalid {
                    path: path.to_string(),
                    message: "key_id must be hex-encoded".into(),
                });
            }
        }
        // Unknown fields are rejected: ADR-0009 makes this extension stricter than Caddy's
        // JSON loader on purpose, so a typo in a budget field cannot silently fall back to a
        // default.
        if let Some(key) = entry.extra.keys().next() {
            return Err(Error::Invalid {
                path: format!("{path}.{key}"),
                message: format!("unknown field {key:?}"),
            });
        }
        let field_error = |field: &str, message: String| Error::Invalid {
            path: format!("{path}.{field}"),
            message,
        };
        // Budget ranges from ADR-0009. `max_inflight_handshakes` is independent of
        // `max_sessions` (1-32 and 1-8 respectively); they are not coupled.
        for (field, value, min, max) in [
            ("max_sessions", entry.max_sessions, 1, 8),
            (
                "max_inflight_handshakes",
                entry.max_inflight_handshakes,
                1,
                32,
            ),
            ("queue_depth", entry.queue_depth, 1, 4096),
        ] {
            if let Some(value) = value {
                if value < min || value > max {
                    return Err(field_error(
                        field,
                        format!("must be between {min} and {max}, got {value}"),
                    ));
                }
            }
        }
        for (field, value) in [
            ("handshake_wait", entry.handshake_wait),
            ("queue_wait", entry.queue_wait),
            ("sign_timeout", entry.sign_timeout),
            ("handshake_timeout", entry.handshake_timeout),
        ] {
            if value == Some(0) {
                return Err(field_error(field, "must be greater than zero".into()));
            }
        }
        // Timeouts must be satisfiable in order, not clamped: the whole handshake must be able
        // to wait for a permit, wait in the queue and complete one `C_Sign`.
        let budget = entry.budget();
        let required = budget
            .handshake_wait
            .checked_add(budget.queue_wait)
            .and_then(|wait| wait.checked_add(budget.sign_timeout));
        match required {
            None => {
                return Err(field_error(
                    "handshake_timeout",
                    "handshake_wait + queue_wait + sign_timeout overflows u64".into(),
                ));
            }
            Some(required) if budget.handshake_timeout < required => {
                return Err(field_error(
                    "handshake_timeout",
                    format!(
                        "must be at least handshake_wait + queue_wait + sign_timeout \
                         ({required} ns), got {} ns",
                        budget.handshake_timeout
                    ),
                ));
            }
            Some(_) => {}
        }
        // Tags follow `load_files` semantics: each tag non-empty and unique.
        if entry.tags.iter().any(|tag| tag.is_empty()) {
            return Err(field_error("tags", "tags must not be empty".into()));
        }
        for (index, tag) in entry.tags.iter().enumerate() {
            if entry.tags[..index].contains(tag) {
                return Err(field_error("tags", format!("duplicate tag {tag:?}")));
            }
        }
        Ok(())
    }

    fn certificate_loader(&self, name: &str, path: &str) -> Result<()> {
        if self
            .registry
            .get_by_key(ModuleKind::TlsCertificateLoader, name)
            .is_none()
        {
            return Err(self.registry.unknown_module(
                ModuleKind::TlsCertificateLoader,
                name.to_string(),
                path.to_string(),
            ));
        }
        Ok(())
    }

    fn automation(&mut self, automation: &TlsAutomation) -> Result<()> {
        for (index, policy) in automation.policies.iter().enumerate() {
            self.tls_policy(policy, &format!("apps.tls.automation.policies[{index}]"))?;
        }
        // Caddy v2.11.9 `AutomationPolicy.makeCertMagicConfig` (`modules/caddytls/automation.go`):
        // on-demand TLS without a permission module is only safe for bounded explicit subjects,
        // policies that use only the internal issuer, or policies with explicitly configured
        // external managers; otherwise provisioning fails. Reject it at validation time with
        // Caddy's wording and a located policy path.
        let on_demand_permission_configured = automation.on_demand.as_ref().is_some_and(|config| {
            config.permission.is_some()
                || config
                    .ask
                    .as_deref()
                    .is_some_and(|ask| !ask.trim().is_empty())
        });
        for (index, policy) in automation.policies.iter().enumerate() {
            self.validate_on_demand_policy(
                policy,
                index,
                on_demand_permission_configured,
                &format!("apps.tls.automation.policies[{index}]"),
            )?;
        }
        if let Some(on_demand) = &automation.on_demand {
            if let Some(permission) = &on_demand.permission {
                let path = "apps.tls.automation.on_demand.permission.module";
                let module = require_module_name(
                    permission.module.as_deref(),
                    path,
                    "TLS on-demand permission",
                    "module",
                )?;
                if self
                    .registry
                    .get_by_key(ModuleKind::TlsPermission, module)
                    .is_none()
                {
                    return Err(self.registry.unknown_module(
                        ModuleKind::TlsPermission,
                        module.to_string(),
                        path.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Caddy v2.11.9 on-demand permission validation for one automation policy.
    ///
    /// Port of `AutomationPolicy.makeCertMagicConfig`'s `noProtections` check: a policy that
    /// enables `on_demand` for default/wildcard subjects with public issuers and no explicit
    /// `get_certificate` managers requires a permission module (`tls.permission.*` or the
    /// deprecated `ask` endpoint). Bounded explicit subjects and internal-only issuers are exempt,
    /// exactly like Caddy.
    fn validate_on_demand_policy(
        &self,
        policy: &AutomationPolicy,
        _index: usize,
        permission_configured: bool,
        path: &str,
    ) -> Result<()> {
        if !policy.on_demand || permission_configured {
            return Ok(());
        }
        let wildcard_or_default = policy.subjects.is_empty()
            || policy
                .subjects
                .iter()
                .any(|subject| subject.starts_with('*'));
        if !wildcard_or_default {
            return Ok(());
        }
        let only_internal_issuer = policy.issuers.len() == 1
            && policy
                .issuers
                .first()
                .and_then(|issuer| issuer.module.as_deref())
                == Some("internal");
        if only_internal_issuer {
            return Ok(());
        }
        let has_explicit_managers = policy
            .get_certificate
            .as_ref()
            .is_some_and(|managers| !managers.is_empty());
        if has_explicit_managers {
            return Ok(());
        }
        Err(Error::invalid(
            format!("{path}.on_demand"),
            "on-demand TLS cannot be enabled without a permission module to prevent abuse; please refer to documentation for details".to_string(),
        ))
    }

    fn tls_policy(&mut self, policy: &AutomationPolicy, path: &str) -> Result<()> {
        self.report.tls_policies += 1;
        for (index, issuer) in policy.issuers.iter().enumerate() {
            let issuer_path = format!("{path}.issuers[{index}]");
            let module_path = format!("{issuer_path}.module");
            let module = require_module_name(
                issuer.module.as_deref(),
                &module_path,
                "TLS issuer",
                "module",
            )?;
            if self
                .registry
                .get_by_key(ModuleKind::TlsIssuer, module)
                .is_none()
            {
                return Err(self.registry.unknown_module(
                    ModuleKind::TlsIssuer,
                    module.to_string(),
                    module_path,
                ));
            }
            if module == "internal" {
                self.internal_issuer_ca(issuer, &issuer_path)?;
            }
            self.validate_dns_provider(issuer, &issuer_path)?;
        }
        if let Some(storage) = &policy.storage {
            validate_storage(storage, self.registry, &format!("{path}.storage"))?;
        }
        Ok(())
    }

    /// An internal issuer must reference a CA that the PKI app defines, or the implicit default
    /// `local` CA. Caddy accepts this at adaptation time but fails provisioning with
    /// "no certificate authority configured with id: ..."; this build rejects it at validation
    /// (the oracle fixture `tls_internal_options` is the regression case, DIV-0070).
    fn internal_issuer_ca(&self, issuer: &ModuleRef, path: &str) -> Result<()> {
        let ca_path = format!("{path}.ca");
        let ca_id =
            match issuer.extra.get("ca") {
                None => "local".to_string(),
                Some(Value::String(value)) if !value.trim().is_empty() => value.clone(),
                Some(Value::String(_)) => return Err(Error::invalid(
                    &ca_path,
                    "certificate authority ID must not be empty (use `local` for the default CA)",
                )),
                Some(_) => {
                    return Err(Error::invalid(
                        &ca_path,
                        "`ca` must be a string certificate authority ID",
                    ))
                }
            };
        let configured = match &self.pki_ca_ids {
            Some(ids) => ids.contains(&ca_id),
            None => ca_id == "local",
        };
        if !configured {
            return Err(Error::invalid(
                &ca_path,
                format!(
                    "no certificate authority configured with id: {ca_id}; configure it in `apps.pki.certificate_authorities` or use the default `local` CA"
                ),
            ));
        }
        Ok(())
    }

    fn validate_dns_provider(&self, issuer: &ModuleRef, path: &str) -> Result<()> {
        let provider = issuer
            .extra
            .get("challenges")
            .and_then(|challenges| challenges.get("dns"))
            .and_then(|dns| dns.get("provider"))
            .and_then(Value::as_str);
        if let Some(provider) = provider {
            if self
                .registry
                .get_by_key(ModuleKind::DnsProvider, provider)
                .is_none()
            {
                return Err(self.registry.unknown_module(
                    ModuleKind::DnsProvider,
                    provider.to_string(),
                    format!("{path}.challenges.dns.provider"),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ModuleRegistry {
        ModuleRegistry::builtin()
    }

    fn minimal_http_config(handler: Value, matcher: Option<Value>) -> Config {
        let mut route = serde_json::json!({
            "handle": [handler],
        });
        if let Some(matcher) = matcher {
            route["match"] = serde_json::json!([matcher]);
        }
        Config::from_value(serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":443"],
                            "routes": [route]
                        }
                    }
                }
            }
        }))
        .expect("model decodes")
    }

    #[test]
    fn accepts_known_handler_and_matcher() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "static_response", "body": "ok"}),
            Some(serde_json::json!({"host": ["example.com"]})),
        );
        let report = validate_config(&config, &registry()).expect("valid");
        assert_eq!(report.servers, 1);
        assert_eq!(report.handlers, 1);
        assert_eq!(report.matchers, 1);
    }

    #[test]
    fn accepts_request_body_handler() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "request_body", "max_size": 1024}),
            None,
        );
        let report = validate_config(&config, &registry()).expect("request_body is registered");
        assert_eq!(report.handlers, 1);
    }

    #[test]
    fn accepts_map_handler() {
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "map",
                "source": "{http.request.uri.path}",
                "destinations": ["{mapped}"],
                "mappings": [{"input": "/old", "outputs": ["/new"]}]
            }),
            None,
        );
        let report = validate_config(&config, &registry()).expect("map is registered");
        assert_eq!(report.handlers, 1);
    }

    #[test]
    fn accepts_file_matcher() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "static_response", "body": "ok"}),
            Some(serde_json::json!({
                "file": {"try_files": ["{http.request.uri.path}", "/index.html"]}
            })),
        );
        let report = validate_config(&config, &registry()).expect("file matcher is registered");
        assert_eq!(report.matchers, 1);
    }

    #[test]
    fn rejects_unknown_handler_with_path_and_name() {
        let config = minimal_http_config(serde_json::json!({"handler": "does_not_exist"}), None);
        let error = validate_config(&config, &registry()).expect_err("unknown handler");
        let message = error.to_string();
        assert!(message.contains("does_not_exist"), "{message}");
        assert!(message.contains("handle[0]"), "{message}");
    }

    #[test]
    fn rejects_unknown_app() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"events": {}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("unknown app");
        assert!(error.to_string().contains("events"));
    }

    #[test]
    fn rejects_duplicate_route_ids() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":80"],
                "routes": [
                    {"@id": "same", "handle": [{"handler": "static_response"}]},
                    {"@id": "same", "handle": [{"handler": "static_response"}]}
                ]
            }}}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("duplicate id");
        assert!(error.to_string().contains("duplicate route id `same`"));
    }

    #[test]
    fn rejects_invalid_listen_address() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": ["not-an-address"],
                "routes": []
            }}}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("bad listen");
        assert!(error.to_string().contains("not-an-address"));
    }

    #[test]
    fn rejects_duplicate_listener_across_servers() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {
                "srv0": {"listen": [":443"], "routes": []},
                "srv1": {"listen": [":443"], "routes": []}
            }}}
        }))
        .unwrap();
        let error = validate_config(&config, &registry()).expect_err("duplicate listener");
        assert!(error.to_string().contains("already used by server `srv0`"));
    }

    #[test]
    fn validates_nested_subroute_handlers() {
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "subroute",
                "routes": [{"handle": [{"handler": "bogus_nested"}]}]
            }),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("nested unknown handler");
        assert!(error.to_string().contains("bogus_nested"));
    }

    #[test]
    fn accepts_subroute_handler_without_routes() {
        // Caddy's `subroute.routes` is optional; the adapter itself emits `{"handler":"subroute"}`
        // for empty nested blocks, so validation must accept it.
        let config = minimal_http_config(serde_json::json!({"handler": "subroute"}), None);
        let report = validate_config(&config, &registry()).expect("empty subroute is valid");
        assert_eq!(report.servers, 1);
        assert_eq!(report.routes, 1);
        assert_eq!(report.handlers, 1);

        // `null` is decoded as an absent list by Caddy too.
        let config = minimal_http_config(
            serde_json::json!({"handler": "subroute", "routes": null}),
            None,
        );
        validate_config(&config, &registry()).expect("null subroute routes is valid");

        // An explicitly empty list is valid as well.
        let config = minimal_http_config(
            serde_json::json!({"handler": "subroute", "routes": []}),
            None,
        );
        validate_config(&config, &registry()).expect("empty subroute routes is valid");
    }

    #[test]
    fn rejects_subroute_with_non_array_routes() {
        for routes in [
            serde_json::json!("not-an-array"),
            serde_json::json!({"handle": []}),
            serde_json::json!(42),
        ] {
            let config = minimal_http_config(
                serde_json::json!({"handler": "subroute", "routes": routes}),
                None,
            );
            let error = validate_config(&config, &registry()).expect_err("bad routes type");
            let message = error.to_string();
            assert!(message.contains("subroute"), "{message}");
            assert!(message.contains("routes"), "{message}");
            assert!(message.contains("array of routes"), "{message}");
            assert!(message.contains("handle[0].routes"), "{message}");
        }
    }

    #[test]
    fn accepts_reverse_proxy_with_dynamic_upstreams() {
        // Shape produced by Caddy's adapter for `reverse_proxy { dynamic srv { ... } }`, including
        // the nested `grace_period` field. The runtime implements srv/a/multi (T-PROXY-036), so
        // validation accepts the construct; source-specific options are validated at provisioning.
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "reverse_proxy",
                "dynamic_upstreams": {
                    "source": "srv",
                    "name": "foo",
                    "refresh": 300_000_000_000_i64,
                    "grace_period": 5_000_000_000_i64
                }
            }),
            None,
        );
        validate_config(&config, &registry()).expect("dynamic-only reverse_proxy is valid");

        // Together with a static pool it is still valid (Caddy allows both).
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}],
                "dynamic_upstreams": {"source": "a"}
            }),
            None,
        );
        validate_config(&config, &registry()).expect("static + dynamic reverse_proxy is valid");

        // A malformed dynamic_upstreams value is still a structural error.
        let config = minimal_http_config(
            serde_json::json!({"handler": "reverse_proxy", "dynamic_upstreams": "srv"}),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("scalar dynamic_upstreams");
        assert!(
            error.to_string().contains("must be an object or array"),
            "{error}"
        );
    }

    #[test]
    fn keeps_structural_reverse_proxy_validation() {
        // Missing `upstreams` remains a structural error when no dynamic upstreams are declared.
        let config = minimal_http_config(serde_json::json!({"handler": "reverse_proxy"}), None);
        let error = validate_config(&config, &registry()).expect_err("missing upstreams");
        assert!(
            error
                .to_string()
                .contains("requires an array field `upstreams`"),
            "{error}"
        );

        // Empty upstreams are still rejected.
        let config = minimal_http_config(
            serde_json::json!({"handler": "reverse_proxy", "upstreams": []}),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("empty upstreams");
        assert!(
            error.to_string().contains("at least one upstream"),
            "{error}"
        );

        // Non-array upstreams are still rejected.
        let config = minimal_http_config(
            serde_json::json!({"handler": "reverse_proxy", "upstreams": "localhost:8080"}),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("bad upstreams type");
        assert!(
            error
                .to_string()
                .contains("requires an array field `upstreams`"),
            "{error}"
        );

        // A normal handler with valid upstreams still validates.
        let config = minimal_http_config(
            serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:8080"}]
            }),
            None,
        );
        let report = validate_config(&config, &registry()).expect("valid reverse_proxy");
        assert_eq!(report.handlers, 1);
    }

    #[test]
    fn validates_per_server_access_log_association() {
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "logs": {
                    "default_logger_name": "fallback",
                    "logger_names": {
                        "example.com": ["one", "two"],
                        "*.internal.example.com": "internal"
                    },
                    "skip_hosts": ["skip.example.com"],
                    "skip_unmapped_hosts": true
                }
            }}}}
        }));
        validate_config(&config, &registry()).expect("per-server logs validate");
    }

    #[test]
    fn validates_listener_wrappers() {
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [
                    {
                        "wrapper": "proxy_protocol",
                        "timeout": "5s",
                        "allow": ["10.0.0.0/8", "2001:db8::/32"],
                        "deny": ["192.0.2.0/24"],
                        "fallback_policy": "IGNORE"
                    },
                    {"wrapper": "tls"}
                ]
            }}}}
        }));
        validate_config(&config, &registry()).expect("valid wrappers");
    }

    #[test]
    fn rejects_invalid_listener_wrappers_with_located_errors() {
        // Unknown wrapper module.
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [{"wrapper": "carrier_pigeon"}]
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown wrapper");
        assert!(error.to_string().contains("carrier_pigeon"), "{error}");
        assert!(
            error
                .to_string()
                .contains("apps.http.servers.srv0.listener_wrappers[0].wrapper"),
            "{error}"
        );

        // Invalid CIDR range.
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [{"wrapper": "proxy_protocol", "deny": ["not-a-cidr"]}]
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("bad CIDR");
        assert!(
            error.to_string().contains("listener_wrappers[0].deny[0]"),
            "{error}"
        );

        // Invalid fallback policy (serde-level, still located at the wrapper).
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [{"wrapper": "proxy_protocol", "fallback_policy": "SOMETIMES"}]
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("bad policy");
        assert!(
            error.to_string().contains("listener_wrappers[0]"),
            "{error}"
        );

        // The implicit TLS marker may not be first and may only appear once.
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [{"wrapper": "tls"}]
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("tls first");
        assert!(error.to_string().contains("must not be first"), "{error}");

        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "listener_wrappers": [
                    {"wrapper": "proxy_protocol"},
                    {"wrapper": "tls"},
                    {"wrapper": "tls"}
                ]
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("duplicate tls");
        assert!(
            error.to_string().contains("only be specified once"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_per_server_log_hosts_with_located_path() {
        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "logs": {"logger_names": {"": ["named"]}}
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("empty host pattern");
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.logs.logger_names"),
            "{message}"
        );
        assert!(message.contains("must not be empty"), "{message}");

        let config = config_from(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "logs": {"skip_hosts": ["bad host"]}
            }}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("whitespace host pattern");
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.logs.skip_hosts[0]"),
            "{message}"
        );
        assert!(message.contains("whitespace"), "{message}");
    }

    #[test]
    fn rejects_reverse_proxy_without_upstreams() {
        let config = minimal_http_config(
            serde_json::json!({"handler": "reverse_proxy", "upstreams": []}),
            None,
        );
        let error = validate_config(&config, &registry()).expect_err("no upstreams");
        assert!(error.to_string().contains("at least one upstream"));
    }

    fn config_from(value: serde_json::Value) -> Config {
        Config::from_value(value).expect("configuration model decodes")
    }

    fn tls_config(tls: serde_json::Value) -> Config {
        config_from(serde_json::json!({"apps": {"tls": tls}}))
    }

    #[test]
    fn validates_typed_logging_storage_and_tls_modules() {
        let config = config_from(serde_json::json!({
            "logging": {
                "sink": {
                    "writer": {"output": "stdout"},
                    "encoder": {"format": "console"}
                },
                "logs": {
                    "default": {
                        "level": "INFO",
                        "writer": {"output": "file", "filename": "/var/log/caddy.log"},
                        "encoder": {"format": "json"},
                        "core": {"module": "mock"}
                    }
                },
                "unknown_preserved_field": true
            },
            "storage": {"module": "file_system", "root": "/data"},
            "apps": {"tls": {
                "certificates": {
                    "load_files": [{"certificate": "c.pem", "key": "k.pem"}],
                    "load_pem": [{"certificate": "c", "key": "k"}],
                    "automate": ["example.com"],
                    "load_storage": {"pairs": []}
                },
                "automation": {
                    "policies": [{
                        "subjects": ["example.com"],
                        "issuers": [
                            {"module": "acme", "challenges": {"dns": {"provider": "cloudflare"}}},
                            {"module": "internal"}
                        ],
                        "storage": {"module": "file_system", "root": "/tls"}
                    }],
                    "on_demand": {"permission": {"module": "http", "endpoint": "https://example.com/ask"}}
                },
                "session_tickets": {"key_source": {"provider": "standard"}},
                "dns": {"name": "cloudflare"}
            }}
        }));
        let report = validate_config(&config, &registry()).expect("typed settings validate");
        assert_eq!(report.tls_policies, 1);
    }

    #[test]
    fn rejects_unknown_log_writer_with_located_error() {
        let config = config_from(serde_json::json!({
            "logging": {"logs": {"default": {"writer": {"output": "syslog"}}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown writer");
        let message = error.to_string();
        assert!(
            message.contains("unknown log writer module `syslog`"),
            "{message}"
        );
        assert!(
            message.contains("logging.logs.default.writer.output"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_log_encoder_with_located_error() {
        let config = config_from(serde_json::json!({
            "logging": {"sink": {"encoder": {"format": "xml"}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown encoder");
        let message = error.to_string();
        assert!(
            message.contains("unknown log encoder module `xml`"),
            "{message}"
        );
        assert!(message.contains("logging.sink.encoder.format"), "{message}");
    }

    #[test]
    fn rejects_unknown_log_core_with_located_error() {
        let config = config_from(serde_json::json!({
            "logging": {"logs": {"default": {"core": {"module": "bogus"}}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown core");
        let message = error.to_string();
        assert!(
            message.contains("unknown log core module `bogus`"),
            "{message}"
        );
        assert!(
            message.contains("logging.logs.default.core.module"),
            "{message}"
        );
    }

    #[test]
    fn rejects_log_module_without_required_name() {
        let config = config_from(serde_json::json!({
            "logging": {"logs": {"default": {"writer": {}}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("missing writer name");
        assert!(error
            .to_string()
            .contains("logging.logs.default.writer.output"));
    }

    #[test]
    fn rejects_unknown_storage_module_with_located_error() {
        let config = config_from(serde_json::json!({"storage": {"module": "redis"}}));
        let error = validate_config(&config, &registry()).expect_err("unknown storage");
        let message = error.to_string();
        assert!(
            message.contains("unknown storage module `redis`"),
            "{message}"
        );
        assert!(message.contains("storage.module"), "{message}");
    }

    #[test]
    fn rejects_storage_without_module() {
        let config = config_from(serde_json::json!({"storage": {"root": "/data"}}));
        let error = validate_config(&config, &registry()).expect_err("missing storage module");
        assert!(error.to_string().contains("storage.module"), "{error}");
        assert!(
            error.to_string().contains("must name a `module`"),
            "{error}"
        );
    }

    #[test]
    fn rejects_unknown_certificate_loader_with_located_error() {
        let config = tls_config(serde_json::json!({
            "certificates": {"load_bogus": []}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown loader");
        let message = error.to_string();
        assert!(
            message.contains("unknown TLS certificate loader module `load_bogus`"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.certificates.load_bogus"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_tls_issuer_with_policy_path() {
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{"issuers": [{"module": "letsencrypt"}]}]}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown issuer");
        let message = error.to_string();
        assert!(
            message.contains("unknown TLS issuer module `letsencrypt`"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.automation.policies[0].issuers[0].module"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_dns_provider_in_issuer_challenges() {
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{
                "issuers": [{"module": "acme", "challenges": {"dns": {"provider": "route53"}}}]
            }]}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown DNS provider");
        let message = error.to_string();
        assert!(
            message.contains("unknown DNS provider module `route53`"),
            "{message}"
        );
        assert!(
            message.contains("policies[0].issuers[0].challenges.dns.provider"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_tls_default_dns_provider() {
        let config = tls_config(serde_json::json!({"dns": {"name": "route53"}}));
        let error = validate_config(&config, &registry()).expect_err("unknown tls dns");
        let message = error.to_string();
        assert!(
            message.contains("unknown DNS provider module `route53`"),
            "{message}"
        );
        assert!(message.contains("apps.tls.dns.name"), "{message}");
    }

    #[test]
    fn rejects_unknown_session_ticket_key_provider() {
        let config = tls_config(serde_json::json!({
            "session_tickets": {"key_source": {"provider": "vault"}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown STEK provider");
        let message = error.to_string();
        assert!(
            message.contains("unknown session ticket key provider module `vault`"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.session_tickets.key_source.provider"),
            "{message}"
        );
    }

    #[test]
    fn rejects_unknown_on_demand_permission_module() {
        let config = tls_config(serde_json::json!({
            "automation": {"on_demand": {"permission": {"module": "dns"}}}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown permission");
        let message = error.to_string();
        assert!(
            message.contains("unknown TLS on-demand permission module `dns`"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.automation.on_demand.permission.module"),
            "{message}"
        );
    }

    /// Adapted JSON from Caddy's
    /// `caddytest/integration/caddyfile_adapt/tls_automation_policies_5.caddyfiletest`
    /// (DIV-0055): the second policy enables `on_demand` with default (unbounded) subjects and no
    /// permission module, which Caddy rejects during provisioning.
    const TLS_AUTOMATION_POLICIES_5_ADAPTED: &str = r#"{
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "listen": [":443"],
                        "routes": [
                            {"match": [{"host": ["a.example.com"]}], "terminal": true},
                            {"match": [{"host": ["b.example.com"]}], "terminal": true}
                        ]
                    }
                }
            },
            "tls": {
                "automation": {
                    "policies": [
                        {"subjects": ["a.example.com", "b.example.com"]},
                        {"on_demand": true}
                    ]
                }
            }
        }
    }"#;

    #[test]
    fn adapted_tls_automation_policies_fixture_rejects_on_demand_without_permission() {
        let config =
            Config::from_value(serde_json::from_str(TLS_AUTOMATION_POLICIES_5_ADAPTED).unwrap())
                .expect("fixture decodes");
        let error = validate_config(&config, &registry()).expect_err("Caddy rejects this policy");
        let message = error.to_string();
        assert!(
            message.contains("apps.tls.automation.policies[1].on_demand"),
            "located policy path missing: {message}"
        );
        assert!(
            message.contains("on-demand TLS cannot be enabled without a permission module"),
            "{message}"
        );
        assert!(message.contains("prevent abuse"), "{message}");
    }

    #[test]
    fn on_demand_with_permission_module_or_bounded_scope_validates() {
        // App-level permission module (Caddy's `tls.permission.http`).
        let config = tls_config(serde_json::json!({
            "automation": {
                "on_demand": {"permission": {
                    "module": "http",
                    "endpoint": "https://example.com/ask"
                }},
                "policies": [{"on_demand": true}]
            }
        }));
        validate_config(&config, &registry()).expect("permission module allows on-demand");

        // Deprecated `ask` endpoint is Caddy's legacy permission mechanism and also counts.
        let config = tls_config(serde_json::json!({
            "automation": {
                "on_demand": {"ask": "https://example.com/ask"},
                "policies": [{"on_demand": true}]
            }
        }));
        validate_config(&config, &registry()).expect("ask endpoint allows on-demand");

        // Bounded explicit (non-wildcard) subjects need no permission (Caddy exempts them).
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{
                "subjects": ["example.com", "www.example.com"],
                "on_demand": true
            }]}
        }));
        validate_config(&config, &registry()).expect("bounded subjects are exempt");

        // Internal-only issuers need no permission (no public PKI pressure).
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{
                "subjects": ["*.internal.example"],
                "on_demand": true,
                "issuers": [{"module": "internal"}]
            }]}
        }));
        validate_config(&config, &registry()).expect("internal issuer is exempt");

        // Explicit external managers allow on-demand even for default subjects.
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{
                "on_demand": true,
                "get_certificate": [{"via": "tailscale"}]
            }]}
        }));
        validate_config(&config, &registry()).expect("explicit managers are exempt");
    }

    #[test]
    fn wildcard_subject_with_public_issuer_still_requires_permission() {
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{
                "subjects": ["*.example.com"],
                "on_demand": true
            }]}
        }));
        let error =
            validate_config(&config, &registry()).expect_err("wildcard requires permission");
        assert!(
            error
                .to_string()
                .contains("on-demand TLS cannot be enabled without a permission module"),
            "{error}"
        );
    }

    #[test]
    fn rejects_unknown_policy_storage_module() {
        let config = tls_config(serde_json::json!({
            "automation": {"policies": [{"storage": {"module": "redis"}}]}
        }));
        let error = validate_config(&config, &registry()).expect_err("unknown policy storage");
        let message = error.to_string();
        assert!(
            message.contains("unknown storage module `redis`"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.automation.policies[0].storage.module"),
            "{message}"
        );
    }

    // ------------------------------------------------------------------------------------------
    // apps.pki and internal issuer CA validation (DIV-0070)
    // ------------------------------------------------------------------------------------------

    fn validate_json(value: serde_json::Value) -> Result<ValidationReport> {
        let config = Config::from_value(value).expect("decodes");
        validate_config(&config, &registry())
    }

    #[test]
    fn accepts_pki_ca_referenced_by_internal_issuer() {
        let report = validate_json(serde_json::json!({
            "apps": {
                "pki": {
                    "certificate_authorities": {
                        "foo": {
                            "name": "Foo CA",
                            "root_common_name": "Foo Root",
                            "intermediate_common_name": "Foo Intermediate",
                            "intermediate_lifetime": 86_400_000_000_000_i64,
                            "install_trust": false,
                            "renewal_window_ratio": 0.2
                        }
                    }
                },
                "tls": {
                    "automation": {
                        "policies": [{
                            "issuers": [{"module": "internal", "ca": "foo", "lifetime": 86_400_000_000_000_i64}]
                        }]
                    }
                }
            }
        }))
        .expect("configured internal CA must validate");
        assert_eq!(report.tls_policies, 1);
    }

    #[test]
    fn rejects_internal_issuer_with_missing_ca_id() {
        // Oracle fixture `tls_internal_options`: Caddy's validator fails with
        // "no certificate authority configured with id: foo"; we reject at validation too.
        let error = validate_json(serde_json::json!({
            "apps": {
                "tls": {
                    "automation": {
                        "policies": [{
                            "issuers": [{"module": "internal", "ca": "foo"}]
                        }]
                    }
                }
            }
        }))
        .expect_err("missing internal CA must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("no certificate authority configured with id: foo"),
            "{message}"
        );
        assert!(
            message.contains("apps.tls.automation.policies[0].issuers[0].ca"),
            "{message}"
        );
    }

    #[test]
    fn accepts_implicit_local_ca_for_internal_issuer() {
        // No apps.pki at all: Caddy provisions the default `local` CA implicitly.
        validate_json(serde_json::json!({
            "apps": {"tls": {"automation": {"policies": [{"issuers": [{"module": "internal"}]}]}}}
        }))
        .expect("implicit local CA must be accepted");

        // Explicit `ca: local` without apps.pki is the same CA.
        validate_json(serde_json::json!({
            "apps": {"tls": {"automation": {"policies": [{"issuers": [{"module": "internal", "ca": "local"}]}]}}}
        }))
        .expect("explicit local CA must be accepted");

        // An empty certificate_authorities map also provisions the default CA.
        validate_json(serde_json::json!({
            "apps": {
                "pki": {"certificate_authorities": {}},
                "tls": {"automation": {"policies": [{"issuers": [{"module": "internal"}]}]}}
            }
        }))
        .expect("empty pki app must accept the implicit local CA");
    }

    #[test]
    fn rejects_implicit_local_ca_when_pki_defines_other_cas() {
        // Once apps.pki defines CAs, Caddy no longer provisions the default local CA.
        let error = validate_json(serde_json::json!({
            "apps": {
                "pki": {"certificate_authorities": {"foo": {"name": "Foo"}}},
                "tls": {"automation": {"policies": [{"issuers": [{"module": "internal"}]}]}}
            }
        }))
        .expect_err("local CA is not implicitly provisioned when apps.pki is non-empty");
        assert!(
            error
                .to_string()
                .contains("no certificate authority configured with id: local"),
            "{error}"
        );
    }

    #[test]
    fn accepts_pki_key_pairs_and_storage() {
        validate_json(serde_json::json!({
            "apps": {
                "pki": {
                    "certificate_authorities": {
                        "local": {
                            "install_trust": false,
                            "root": {
                                "certificate": "/path/cert.pem",
                                "private_key": "/path/key.pem",
                                "format": "pem_file"
                            },
                            "intermediate": {
                                "certificate": "/path/inter.pem",
                                "private_key": "/path/inter.key"
                            },
                            "storage": {"module": "file_system", "root": "/data"}
                        }
                    }
                },
                "tls": {"automation": {"policies": [{"issuers": [{"module": "internal"}]}]}}
            }
        }))
        .expect("explicit local CA with key pairs and storage validates");
    }

    #[test]
    fn rejects_unknown_pki_and_ca_fields_loudly() {
        let error = validate_json(serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {}, "future_pki_field": true}}
        }))
        .expect_err("unknown pki app field");
        assert!(
            error
                .to_string()
                .contains("unknown PKI app field(s): future_pki_field"),
            "{error}"
        );

        let error = validate_json(serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"future_ca_field": 1}
            }}}
        }))
        .expect_err("unknown CA field");
        assert!(
            error
                .to_string()
                .contains("unknown certificate authority field(s): future_ca_field"),
            "{error}"
        );

        let error = validate_json(serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"root": {"future_key_pair_field": true}}
            }}}
        }))
        .expect_err("unknown key-pair field");
        assert!(
            error
                .to_string()
                .contains("unknown key-pair field(s): future_key_pair_field"),
            "{error}"
        );

        let error = validate_json(serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"root": {"certificate": "/c", "format": "pkcs12"}}
            }}}
        }))
        .expect_err("unsupported key-pair format");
        assert!(
            error
                .to_string()
                .contains("unsupported key-pair format `pkcs12`"),
            "{error}"
        );

        let error = validate_json(serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"storage": {"module": "bogus_storage"}}
            }}}
        }))
        .expect_err("unknown storage module");
        assert!(error.to_string().contains("bogus_storage"), "{error}");
    }

    #[test]
    fn rejects_invalid_ca_identifiers_and_numbers() {
        for value in [
            serde_json::json!({"apps": {"pki": {"certificate_authorities": {"": {}}}}}),
            serde_json::json!({"apps": {"pki": {"certificate_authorities": {
                "local": {"id": "other"}
            }}}}),
            serde_json::json!({"apps": {"pki": {"certificate_authorities": {
                "local": {"intermediate_lifetime": -1}
            }}}}),
            serde_json::json!({"apps": {"pki": {"certificate_authorities": {
                "local": {"renewal_window_ratio": 1.5}
            }}}}),
            serde_json::json!({"apps": {"pki": {"certificate_authorities": {
                "local": {"root": {"certificate": ""}}
            }}}}),
        ] {
            assert!(validate_json(value.clone()).is_err(), "must reject {value}");
        }
    }

    #[test]
    fn rejects_internal_issuer_with_non_string_ca() {
        let error = validate_json(serde_json::json!({
            "apps": {"tls": {"automation": {"policies": [{
                "issuers": [{"module": "internal", "ca": 42}]
            }]}}}
        }))
        .expect_err("non-string ca");
        assert!(
            error.to_string().contains("`ca` must be a string"),
            "{error}"
        );
    }

    fn server_config(fields: Value) -> Config {
        let mut server = serde_json::json!({"listen": [":8080"], "routes": []});
        if let Value::Object(fields) = fields {
            for (key, value) in fields {
                server[key] = value;
            }
        }
        Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": server}}}
        }))
        .expect("test config decodes")
    }

    #[test]
    fn accepts_caddy_duration_and_numeric_server_limits() {
        let config = server_config(serde_json::json!({
            "read_timeout": "5s",
            "write_timeout": 2_000_000_000_i64,
            "idle_timeout": "2d",
            "read_header_timeout": "1m",
            // Caddy accepts negative durations; provisioning treats them as disabled.
            "keepalive_interval": "-1s",
            "read_idle_timeout": 30_000_000_000_i64,
            "write_idle_timeout": "0",
            "max_header_bytes": 16_384,
            "max_request_body_size": 1_048_576,
            "max_connections": 10,
            "keepalive_count": 3
        }));
        let report = validate_config(&config, &registry()).expect("valid server limits");
        assert_eq!(report.servers, 1);
    }

    #[test]
    fn rejects_malformed_durations_and_numeric_limits_at_load() {
        for (fields, expected_path) in [
            (serde_json::json!({"read_timeout": "soon"}), "read_timeout"),
            (serde_json::json!({"idle_timeout": 1.5}), "idle_timeout"),
            (serde_json::json!({"write_timeout": true}), "write_timeout"),
            (
                serde_json::json!({"read_header_timeout": "5"}),
                "read_header_timeout",
            ),
            (
                serde_json::json!({"keepalive_interval": "1x"}),
                "keepalive_interval",
            ),
            (
                serde_json::json!({"max_header_bytes": "16k"}),
                "max_header_bytes",
            ),
            (
                serde_json::json!({"max_request_body_size": "1MiB"}),
                "max_request_body_size",
            ),
            (
                serde_json::json!({"max_connections": -1}),
                "max_connections",
            ),
            (
                serde_json::json!({"keepalive_count": 1.5}),
                "keepalive_count",
            ),
        ] {
            let config = server_config(fields.clone());
            let error = validate_config(&config, &registry())
                .expect_err("malformed server limit must fail validation");
            let message = error.to_string();
            assert!(
                message.contains(expected_path) && message.contains("apps.http.servers.srv0"),
                "error for {fields} must name the located field, got: {message}"
            );
        }
    }

    #[test]
    fn accepts_valid_pkcs11_entry() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "module": "/usr/lib/libsofthsm2.so",
                            "token": "softhsm-token",
                            "key_label": "server-key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "PKCS11_PIN"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let report =
            validate_config(&config, &registry()).expect("valid pkcs11 entry passes validation");
        assert_eq!(report.servers, 0);
    }

    #[test]
    fn rejects_pkcs11_token_and_slot() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "slot": 1,
                            "key_label": "key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "pin"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error = validate_config(&config, &registry()).expect_err("token+slot must fail");
        let message = error.to_string();
        assert!(message.contains("mutually exclusive"), "{message}");
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0]"),
            "{message}"
        );
    }

    #[test]
    fn rejects_pkcs11_no_token_no_slot() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "key_label": "key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "pin"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error = validate_config(&config, &registry()).expect_err("no token/slot must fail");
        let message = error.to_string();
        assert!(message.contains("one of token or slot"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_key_label_and_key_id() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "key_label": "key",
                            "key_id": "deadbeef",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "pin"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error = validate_config(&config, &registry()).expect_err("key_label+key_id must fail");
        let message = error.to_string();
        assert!(message.contains("mutually exclusive"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_certificate_and_certificate_pem() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "key_label": "key",
                            "certificate": "/etc/certs/chain.pem",
                            "certificate_pem": "-----BEGIN CERTIFICATE-----\\\\nMIIB...\\\\n-----END CERTIFICATE-----\\\\n",
                            "pin_source": "env",
                            "pin": "pin"
                        }]
                    }
                }
            }
        })).expect("model decodes");
        let error = validate_config(&config, &registry())
            .expect_err("certificate+certificate_pem must fail");
        let message = error.to_string();
        assert!(message.contains("mutually exclusive"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_env_without_pin() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "key_label": "key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error = validate_config(&config, &registry()).expect_err("env without pin must fail");
        let message = error.to_string();
        assert!(message.contains("requires pin"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_file_without_pin_file() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "key_label": "key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "file"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error =
            validate_config(&config, &registry()).expect_err("file without pin_file must fail");
        let message = error.to_string();
        assert!(message.contains("requires pin_file"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_bad_hex_key_id() {
        let config = Config::from_value(serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "token": "tok",
                            "key_id": "xyz",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "pin"
                        }]
                    }
                }
            }
        }))
        .expect("model decodes");
        let error = validate_config(&config, &registry()).expect_err("bad hex key_id must fail");
        let message = error.to_string();
        assert!(message.contains("hex-encoded"), "{message}");
    }

    fn pkcs11_entry_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut entry = serde_json::json!({
            "module": "/usr/lib/libsofthsm2.so",
            "token": "softhsm-token",
            "key_label": "server-key",
            "certificate": "/etc/certs/chain.pem",
            "pin_source": "env",
            "pin": "PKCS11_PIN"
        });
        for (key, value) in overrides.as_object().expect("overrides object") {
            entry[key] = value.clone();
        }
        entry
    }

    fn pkcs11_config_with(overrides: serde_json::Value) -> Config {
        Config::from_value(serde_json::json!({
            "apps": {"tls": {"certificates": {"pkcs11": [pkcs11_entry_json(overrides)]}}}
        }))
        .expect("model decodes")
    }

    fn pkcs11_error(overrides: serde_json::Value) -> String {
        validate_config(&pkcs11_config_with(overrides), &registry())
            .expect_err("pkcs11 entry must be rejected")
            .to_string()
    }

    #[test]
    fn accepts_pkcs11_budget_fields() {
        let config = pkcs11_config_with(serde_json::json!({
            "max_sessions": 2,
            "max_inflight_handshakes": 4,
            "handshake_wait": 2000000000u64,
            "queue_depth": 128,
            "queue_wait": 3000000000u64,
            "sign_timeout": 6000000000u64,
            "handshake_timeout": 20000000000u64,
            "tags": ["example", "tpm"]
        }));
        let report = validate_config(&config, &registry())
            .expect("full pkcs11 budget entry passes validation");
        assert_eq!(report.servers, 0);
    }

    #[test]
    fn rejects_pkcs11_out_of_range_budget_fields() {
        for (field, value) in [
            ("max_sessions", 0),
            ("max_sessions", 9),
            ("max_inflight_handshakes", 0),
            ("max_inflight_handshakes", 33),
            ("queue_depth", 0),
            ("queue_depth", 4097),
        ] {
            let message = pkcs11_error(serde_json::json!({ field: value }));
            assert!(
                message.contains(&format!("apps.tls.certificates.pkcs11[0].{field}")),
                "{field}={value}: {message}"
            );
        }
    }

    #[test]
    fn rejects_pkcs11_zero_sign_timeout() {
        let message = pkcs11_error(serde_json::json!({ "sign_timeout": 0 }));
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0].sign_timeout"),
            "{message}"
        );
    }

    #[test]
    fn rejects_pkcs11_timeout_ordering_violation() {
        // handshake_wait + queue_wait + sign_timeout = 7s > handshake_timeout = 1ns.
        let message = pkcs11_error(serde_json::json!({
            "handshake_wait": 1000000000,
            "queue_wait": 1000000000,
            "sign_timeout": 5000000000u64,
            "handshake_timeout": 1
        }));
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0].handshake_timeout"),
            "{message}"
        );
        assert!(message.contains("at least"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_unknown_field() {
        let message = pkcs11_error(serde_json::json!({ "max_session": 2 }));
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0].max_session"),
            "{message}"
        );
        assert!(message.contains("unknown field"), "{message}");
    }

    #[test]
    fn rejects_pkcs11_empty_tag() {
        let message = pkcs11_error(serde_json::json!({ "tags": ["ok", ""] }));
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0].tags"),
            "{message}"
        );
    }

    #[test]
    fn rejects_pkcs11_duplicate_tag() {
        let message = pkcs11_error(serde_json::json!({ "tags": ["example", "example"] }));
        assert!(
            message.contains("apps.tls.certificates.pkcs11[0].tags"),
            "{message}"
        );
        assert!(message.contains("duplicate tag"), "{message}");
    }

    /// Name of the socket file the admin-socket tests describe inside their temp directory.
    const ADMIN_SOCKET_FILE: &str = "caddy-admin.sock";

    /// A private directory for an admin-socket test, removed by the caller.
    ///
    /// The directory comes from `root` unless that would push `root/<name>/{ADMIN_SOCKET_FILE}`
    /// past [`UNIX_SOCKET_PATH_MAX`] — a long `TMPDIR` would then make the test fail for a
    /// path-length reason instead of the behaviour under test — in which case the short fixed
    /// parent `/tmp` is used instead.
    fn admin_socket_temp_dir_in(root: &std::path::Path, label: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("caddy-rs-admin-sock-{label}-{}-{nonce}", std::process::id());
        let mut path = root.join(&name);
        let socket_len = 1 + ADMIN_SOCKET_FILE.len();
        if path.to_string_lossy().len() + socket_len > UNIX_SOCKET_PATH_MAX {
            path = std::path::PathBuf::from("/tmp").join(&name);
        }
        std::fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn admin_socket_temp_dir(label: &str) -> std::path::PathBuf {
        admin_socket_temp_dir_in(&std::env::temp_dir(), label)
    }

    fn admin_listen_error(listen: &str) -> String {
        let config = Config::from_value(serde_json::json!({ "admin": { "listen": listen } }))
            .expect("model decodes");
        validate_config(&config, &registry())
            .expect_err("invalid admin listen must fail")
            .to_string()
    }

    #[test]
    fn admin_socket_temp_dir_falls_back_when_temp_root_is_too_long() {
        // A `TMPDIR` long enough to overflow `sockaddr_un` must not make the admin-socket tests
        // fail for the wrong reason: the helper falls back to the short fixed parent `/tmp`.
        let long_root =
            std::path::PathBuf::from(format!("/tmp/{}", "t".repeat(UNIX_SOCKET_PATH_MAX)));
        let dir = admin_socket_temp_dir_in(&long_root, "fallback");
        let socket = format!("unix/{}/{ADMIN_SOCKET_FILE}", dir.display());
        assert!(
            socket.len() - "unix/".len() <= UNIX_SOCKET_PATH_MAX,
            "socket path not bindable: {socket}"
        );
        assert_eq!(dir.parent(), Some(std::path::Path::new("/tmp")));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn accepts_admin_unix_socket_path_in_writable_directory() {
        let dir = admin_socket_temp_dir("accept");
        let listen = format!("unix/{}/caddy-admin.sock", dir.display());
        let config = Config::from_value(serde_json::json!({ "admin": { "listen": listen } }))
            .expect("model decodes");
        validate_config(&config, &registry()).expect("writable parent must validate");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn rejects_relative_admin_unix_socket_path() {
        // `unix/run/caddy.sock` is the relative spelling; `unix//run/caddy.sock` would be the
        // absolute `/run/caddy.sock`.
        let message = admin_listen_error("unix/caddy-admin.sock");
        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("unix/caddy-admin.sock"), "{message}");
        assert!(message.contains("must be absolute"), "{message}");
    }

    #[test]
    fn rejects_admin_unix_socket_path_with_missing_parent() {
        let message = admin_listen_error("unix//nonexistent-caddy-admin-dir/caddy-admin.sock");
        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("nonexistent-caddy-admin-dir"), "{message}");
        assert!(message.contains("does not exist"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_admin_unix_socket_path_with_non_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = admin_socket_temp_dir("readonly");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555))
            .expect("chmod read-only");
        let listen = format!("unix/{}/caddy-admin.sock", dir.display());
        let message = admin_listen_error(&listen);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod writable");
        std::fs::remove_dir_all(&dir).expect("cleanup");

        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("not writable"), "{message}");
        assert!(message.contains(&dir.display().to_string()), "{message}");
    }

    #[test]
    fn rejects_admin_unix_socket_path_over_sockaddr_un_limit() {
        let long = format!("unix//run/{}.sock", "a".repeat(UNIX_SOCKET_PATH_MAX));
        let message = admin_listen_error(&long);
        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("sockaddr_un"), "{message}");
        assert!(message.contains("107"), "{message}");
    }

    #[test]
    fn unix_socket_path_length_boundary_matches_sockaddr_un() {
        // The limit applies to the absolute path (after `unix/`), and `sun_path` must also hold
        // the terminating NUL: exactly `UNIX_SOCKET_PATH_MAX` bytes bind, one more does not.
        // A fixed short parent keeps the boundary arithmetic independent of `TMPDIR` length, so a
        // long temporary directory cannot underflow the padding computation.
        let parent = "/tmp";
        let pad = |length: usize| "a".repeat(length - parent.len() - 1);

        let fits = pad(UNIX_SOCKET_PATH_MAX);
        let listen = format!("unix/{parent}/{fits}");
        let config = Config::from_value(serde_json::json!({ "admin": { "listen": listen } }))
            .expect("model decodes");
        validate_config(&config, &registry()).expect("path at the limit must validate");

        let too_long = pad(UNIX_SOCKET_PATH_MAX + 1);
        let listen = format!("unix/{parent}/{too_long}");
        let message = admin_listen_error(&listen);
        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("108 bytes"), "{message}");
        assert!(message.contains("107-byte"), "{message}");
    }

    #[test]
    fn rejects_admin_unix_socket_path_with_null_byte() {
        let message = admin_listen_error("unix//run/caddy\0-admin.sock");
        assert!(message.contains("admin.listen"), "{message}");
        assert!(message.contains("null byte"), "{message}");
    }
}
