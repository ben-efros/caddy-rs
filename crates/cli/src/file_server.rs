//! `caddy-rs file-server`: a production-ready static file server.
//!
//! This is the port of Caddy v2.11.9's `caddy file-server`
//! (`external/caddy/modules/caddyhttp/fileserver/command.go`): it builds the same in-memory
//! configuration — admin disabled with `config.persist=false`, one HTTP server named `static`
//! with Caddy's quick-server limits, and a single route whose handlers are `encode` (unless
//! `--no-compress`), `templates` (with `--templates`) and `file_server` — and serves it with the
//! same runtime as `caddy-rs run`.
//!
//! Flags whose capability this build does not have are rejected before anything is started, with
//! a located error naming the flag and the missing module/feature; none of them is silently
//! ignored. `--domain` is rejected because this command does not wire automatic HTTPS: stock
//! switches the default listener to `:443` and relies on Caddy's automatic HTTPS, and this build
//! must not silently serve plaintext on `:80` instead.
//!
//! Supported: `--root`, `--listen` (default `:80`), `--browse`, `--templates` (when the
//! `http.handlers.templates` module is compiled in), `--access-log`, `--no-compress`,
//! `--precompressed` (gzip, br and zstd, the formats this build's `file_server` ships with).
//!
//! Divergences from stock, all documented in `docs/CLI.md`: the browse page has no
//! `reveal_symlinks`/`file_limit` support, so `--reveal-symlinks` and `--file-limit` are rejected
//! rather than silently accepted; `--debug` is rejected because this build has no debug-level
//! internal logging; `--domain` is rejected as described above.

use std::sync::Arc;

use anyhow::{Context, Result};
use caddy_rs_core::{
    validate_config, AdminConfig, Apps, Config, GenerationStore, HttpApp, HttpServer, Logging,
    ModuleRegistry, Route, ServerLogConfig,
};
use caddy_rs_server::ServerRuntime;
use serde_json::{json, Map, Value};

use crate::CliExit;

/// Caddy's `buildHTTPServer` read-header timeout (`ReadHeaderTimeout: 10 * time.Second`).
const READ_HEADER_TIMEOUT: &str = "10s";
/// Caddy's `buildHTTPServer` idle timeout (`IdleTimeout: 30 * time.Second`).
const IDLE_TIMEOUT: &str = "30s";
/// Caddy's `buildHTTPServer` maximum header size (`MaxHeaderBytes: 1024 * 10`).
const MAX_HEADER_BYTES: u64 = 10 * 1024;
/// Caddy's default listener address when neither `--listen` nor `--domain` is given.
const DEFAULT_LISTEN: &str = ":80";
/// Stock `defaultDirEntryLimit`, the default for `--file-limit`.
const DEFAULT_FILE_LIMIT: usize = 10_000;
/// The precompressed formats this build's `file_server` serves.
const PRECOMPRESSED_FORMATS: [&str; 3] = ["gzip", "br", "zstd"];

/// Arguments for `caddy-rs file-server`, after clap parsing.
pub(crate) struct Args {
    /// `--domain` / `-d` (unsupported: implies automatic HTTPS).
    pub(crate) domain: String,
    /// `--root` / `-r`.
    pub(crate) root: String,
    /// `--listen` / `-l` (default `:80`).
    pub(crate) listen: String,
    /// `--browse` / `-b`.
    pub(crate) browse: bool,
    /// `--reveal-symlinks` (unsupported by the browse implementation).
    pub(crate) reveal_symlinks: bool,
    /// `--templates` / `-t`.
    pub(crate) templates: bool,
    /// `--access-log` / `-a`.
    pub(crate) access_log: bool,
    /// `--debug` / `-v` (unsupported: no debug-level internal logging).
    pub(crate) debug: bool,
    /// `--file-limit` / `-f` (unsupported: no directory-entry limit).
    pub(crate) file_limit: Option<usize>,
    /// `--no-compress`.
    pub(crate) no_compress: bool,
    /// `--precompressed` / `-p` (repeatable or comma-separated).
    pub(crate) precompressed: Vec<String>,
}

/// Run `caddy-rs file-server`.
pub(crate) async fn run(args: Args) -> Result<()> {
    let registry = crate::builtin_module_registry();
    check_flags(&args, &registry)?;

    let listen = if args.listen.is_empty() {
        DEFAULT_LISTEN.to_string()
    } else {
        args.listen.clone()
    };
    let config = build_config(&args, &listen)?;
    validate_config(&config, &registry)
        .context("the file-server configuration is not valid in this build")?;

    let store = Arc::new(GenerationStore::new(Arc::new(registry)));
    store
        .load(config)
        .context("cannot activate the file-server configuration")?;
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).without_socket_activation();
    runtime
        .apply()
        .await
        .context("cannot start the file-server listener")?;

    // Stock logs this through `log.Printf` (stderr) after `caddy.Run` succeeds, with the
    // configured listen address rather than the bound one.
    eprintln!("Caddy serving static files on {listen}");

    let channels = crate::signals::shutdown_channels()?;
    runtime
        .run_with_force(channels.shutdown, channels.force)
        .await
        .context("file-server failed")?;
    Ok(())
}

/// Reject every flag whose capability this build does not have, before anything is started.
///
/// Stock returns `caddy.ExitCodeFailedStartup` (1) for a startup failure; every rejection here
/// uses the same code. All checks run before the generation store is loaded, so a rejected flag
/// can never leave a listener behind.
fn check_flags(args: &Args, registry: &ModuleRegistry) -> Result<()> {
    if !args.domain.is_empty() {
        return Err(located(
            "--domain",
            "automatic HTTPS is not supported by `caddy-rs file-server`: stock switches the \
             default listener to :443 and obtains a certificate for the domain, which this \
             command does not wire. Serve the files from a Caddyfile/JSON configuration with a \
             site address instead, or re-run without --domain",
        ));
    }
    if args.debug {
        return Err(located(
            "--debug",
            "caddy-rs has no debug-level internal logging; re-run without --debug",
        ));
    }
    if args.reveal_symlinks {
        return Err(located(
            "--reveal-symlinks",
            "the file_server browse implementation in this build lists entry names only and \
             does not reveal symlink targets; re-run without --reveal-symlinks",
        ));
    }
    if let Some(limit) = args.file_limit {
        return Err(located(
            "--file-limit",
            &format!(
                "the file_server browse implementation in this build has no directory-entry \
                 limit (stock's default is {DEFAULT_FILE_LIMIT}); re-run without --file-limit \
                 (given {limit})"
            ),
        ));
    }
    for format in &args.precompressed {
        if !PRECOMPRESSED_FORMATS.contains(&format.as_str()) {
            return Err(located(
                &format!("--precompressed {format}"),
                &format!(
                    "module `http.precompressed.{format}` is not available in this build; \
                     supported formats: {}",
                    PRECOMPRESSED_FORMATS.join(", ")
                ),
            ));
        }
    }
    if args.templates && !registry.contains("http.handlers.templates") {
        return Err(located(
            "--templates",
            "module `http.handlers.templates` is not compiled into this build; rebuild with the \
             `templates` feature or re-run without --templates",
        ));
    }
    if !args.no_compress && !registry.contains("http.handlers.encode") {
        return Err(located(
            "compression",
            "module `http.handlers.encode` is not compiled into this build; re-run with \
             --no-compress",
        ));
    }
    if !registry.contains("http.handlers.file_server") {
        return Err(located(
            "file_server",
            "module `http.handlers.file_server` is not compiled into this build",
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

/// Build the in-memory configuration `file-server` runs.
///
/// Mirrors stock: admin disabled with `config.persist=false`, one `static` server with Caddy's
/// quick-server limits, and one route with `encode` (unless `--no-compress`), `templates` (with
/// `--templates`) and `file_server` handlers in that order.
fn build_config(args: &Args, listen: &str) -> Result<Config> {
    let mut handlers: Vec<Value> = Vec::new();

    if !args.no_compress {
        handlers.push(json!({
            "handler": "encode",
            "encodings": { "zstd": {}, "gzip": {} },
            "prefer": ["zstd", "gzip"],
        }));
    }

    if args.templates {
        let mut templates = Map::new();
        templates.insert("handler".to_string(), Value::String("templates".into()));
        // Stock sets `FileRoot: root`; an empty root means the handler default (`{http.vars.root}`,
        // falling back to `.`), so the key is omitted rather than sent as an empty path.
        if !args.root.is_empty() {
            templates.insert("file_root".to_string(), Value::String(args.root.clone()));
        }
        handlers.push(Value::Object(templates));
    }

    let mut file_server = Map::new();
    file_server.insert("handler".to_string(), Value::String("file_server".into()));
    // An empty `--root` leaves `root` unset, which the handler expands to `{http.vars.root}`
    // (unset here) and therefore `.`, matching stock's current-directory default.
    if !args.root.is_empty() {
        file_server.insert("root".to_string(), Value::String(args.root.clone()));
    }
    if args.browse {
        // Stock emits `browse: {reveal_symlinks, file_limit}`; this build's file_server accepts
        // the boolean form only (see the module docs).
        file_server.insert("browse".to_string(), Value::Bool(true));
    }
    if !args.precompressed.is_empty() {
        let mut precompressed = Map::new();
        for format in &args.precompressed {
            precompressed.insert(format.clone(), json!({}));
        }
        file_server.insert("precompressed".to_string(), Value::Object(precompressed));
        file_server.insert(
            "precompressed_order".to_string(),
            Value::Array(
                args.precompressed
                    .iter()
                    .map(|format| Value::String(format.clone()))
                    .collect(),
            ),
        );
    }
    handlers.push(Value::Object(file_server));

    let route = Route {
        handle: handlers,
        ..Default::default()
    };

    let mut server = HttpServer {
        listen: vec![listen.to_string()],
        routes: vec![route],
        idle_timeout: Some(Value::String(IDLE_TIMEOUT.to_string())),
        ..Default::default()
    };
    server.extra.insert(
        "read_header_timeout".to_string(),
        Value::String(READ_HEADER_TIMEOUT.to_string()),
    );
    server.extra.insert(
        "max_header_bytes".to_string(),
        Value::from(MAX_HEADER_BYTES),
    );
    if args.access_log {
        server.logs = Some(ServerLogConfig::default());
    }

    let mut http_servers = std::collections::BTreeMap::new();
    http_servers.insert("static".to_string(), server);

    // Caddy disables the admin endpoint and config persistence for `file-server`.
    let mut admin_extra = std::collections::BTreeMap::new();
    admin_extra.insert("config".to_string(), json!({ "persist": false }));

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
            tls: None,
            pki: None,
            extra: std::collections::BTreeMap::new(),
        }),
        ..Default::default()
    })
}
