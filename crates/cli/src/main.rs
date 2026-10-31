//! `caddy-rs` command-line interface.
//!
//! Command surface follows Caddy's CLI where it is meaningful for this build: `adapt`, `validate`,
//! `run`, `reload`, `stop`, `list-modules`, `version`. See `docs/compatibility/CADDYFILE.md` and
//! the program repository's compatibility register for the supported configuration surface.

mod signals;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Context};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};

use caddy_rs_admin::AdminResponse;
use caddy_rs_config::CaddyfileAdapter;
use caddy_rs_core::{Config, ConfigAdapter, GenerationStore, ModuleRegistry, VERSION};
use caddy_rs_server::ServerRuntime;

#[derive(Debug, Parser)]
#[command(
    name = "caddy-rs",
    about = "A Rust implementation of the Caddy web server",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the version.
    Version {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// List modules compiled into this build.
    ListModules {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Adapt a user-facing config to Caddy JSON.
    Adapt {
        /// Configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
        /// Indented output.
        #[arg(long)]
        pretty: bool,
        /// Write output to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate a configuration without running it.
    Validate {
        /// Configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
    },
    /// Run the server with a configuration.
    Run {
        /// Configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
    },
    /// Load a new configuration into a running server through its admin API.
    Reload {
        /// Configuration file.
        #[arg(short, long)]
        config: PathBuf,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
        /// Admin API address.
        #[arg(long, default_value = "localhost:2019")]
        admin: String,
    },
    /// Stop a running server through its admin API.
    Stop {
        /// Admin API address.
        #[arg(long, default_value = "localhost:2019")]
        admin: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("caddy-rs: error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Version { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "version": VERSION,
                        "caddy_compat_baseline": caddy_rs_core::CADDY_COMPAT_BASELINE,
                    })
                );
            } else {
                println!(
                    "caddy-rs {VERSION} (Caddy configuration baseline {})",
                    caddy_rs_core::CADDY_COMPAT_BASELINE
                );
            }
        }
        Command::ListModules { json } => {
            let registry = ModuleRegistry::builtin();
            if json {
                let modules: Vec<_> = registry
                    .modules()
                    .map(|module| {
                        serde_json::json!({
                            "id": module.id,
                            "json_key": module.json_key,
                            "kind": module.kind.label(),
                            "summary": module.summary,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!({ "modules": modules }));
            } else {
                for module in registry.modules() {
                    println!("{}", module.id);
                }
            }
        }
        Command::Adapt {
            config,
            adapter,
            pretty,
            output,
        } => {
            let adapted = adapt(&config, adapter.as_deref())?;
            let json = if pretty {
                serde_json::to_vec_pretty(&adapted.config)
            } else {
                serde_json::to_vec(&adapted.config)
            }
            .context("cannot serialize adapted configuration")?;
            for warning in &adapted.warnings {
                eprintln!("warning: {warning}");
            }
            match output {
                Some(path) => std::fs::write(&path, &json)
                    .with_context(|| format!("cannot write output `{}`", path.display()))?,
                None => println!("{}", String::from_utf8_lossy(&json)),
            }
        }
        Command::Validate { config, adapter } => {
            let (config, warnings) = load_validated(&config, adapter.as_deref())?;
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            let _ = config;
            println!("Valid configuration");
        }
        Command::Run { config, adapter } => {
            let (config, warnings) = load_validated(&config, adapter.as_deref())?;
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            let store = Arc::new(GenerationStore::new(Arc::new(ModuleRegistry::builtin())));
            let loaded = store
                .load(config)
                .context("cannot activate configuration")?;
            let mut runtime = ServerRuntime::new(Arc::clone(&store));
            let status = runtime.apply().await.context("cannot start listeners")?;
            eprintln!(
                "caddy-rs: configuration active (generation {})",
                loaded.generation.id()
            );
            for (configured, bound) in &status.listeners {
                if configured == bound {
                    eprintln!("caddy-rs: listening on {bound}");
                } else {
                    eprintln!("caddy-rs: listening on {configured} (bound {bound})");
                }
            }
            if let Some(admin) = &status.admin {
                eprintln!("caddy-rs: admin API listening on {admin}");
            }
            let shutdown = signals::shutdown_channel()?;
            runtime.run(shutdown).await.context("runtime failed")?;
        }
        Command::Reload {
            config,
            adapter,
            admin,
        } => {
            let (config, warnings) = load_validated(&config, adapter.as_deref())?;
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            let body = config.to_vec().context("cannot encode configuration")?;
            let response = admin_request(&admin, "POST", "/load", Bytes::from(body)).await?;
            ensure_admin_success(&response)?;
            eprintln!("configuration reloaded");
        }
        Command::Stop { admin } => {
            let response = admin_request(&admin, "POST", "/stop", Bytes::new()).await?;
            ensure_admin_success(&response)?;
            eprintln!("server stopped");
        }
    }
    Ok(())
}

fn infer_adapter(config: &Path, explicit: Option<&str>) -> Option<String> {
    if let Some(explicit) = explicit {
        return Some(explicit.to_string());
    }
    let name = config
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if name.starts_with("Caddyfile") {
        Some("caddyfile".to_string())
    } else {
        None
    }
}

fn adapt(config: &Path, adapter: Option<&str>) -> anyhow::Result<caddy_rs_core::AdaptedConfig> {
    let input = std::fs::read(config)
        .with_context(|| format!("cannot read config `{}`", config.display()))?;
    match infer_adapter(config, adapter).as_deref() {
        Some("caddyfile") => CaddyfileAdapter
            .adapt(&input)
            .with_context(|| format!("cannot adapt `{}`", config.display())),
        Some("json") | None => {
            let value: serde_json::Value = serde_json::from_slice(&input)
                .with_context(|| format!("`{}` is not valid JSON", config.display()))?;
            Ok(caddy_rs_core::AdaptedConfig {
                config: value,
                warnings: Vec::new(),
            })
        }
        Some(other) => {
            bail!("unsupported adapter `{other}`; supported adapters are caddyfile and json")
        }
    }
}

fn load_validated(config: &Path, adapter: Option<&str>) -> anyhow::Result<(Config, Vec<String>)> {
    let adapted = adapt(config, adapter)?;
    let model = Config::from_value(adapted.config).with_context(|| {
        format!(
            "`{}` does not match the configuration model",
            config.display()
        )
    })?;
    let registry = ModuleRegistry::builtin();
    caddy_rs_core::validate_config(&model, &registry)
        .with_context(|| format!("`{}` is not a valid configuration", config.display()))?;
    Ok((model, adapted.warnings))
}

async fn admin_request(
    admin: &str,
    method: &str,
    path: &str,
    body: Bytes,
) -> anyhow::Result<AdminResponse> {
    let admin = admin
        .strip_prefix("http://")
        .or_else(|| admin.strip_prefix("https://"))
        .unwrap_or(admin);
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{admin}{path}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(body))
        .context("cannot build admin request")?;
    let response = client
        .request(request)
        .await
        .with_context(|| format!("cannot reach admin API at `{admin}`"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("cannot read admin response")?
        .to_bytes();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain"),
    );
    Ok(AdminResponse {
        status,
        headers,
        body,
    })
}

fn ensure_admin_success(response: &AdminResponse) -> anyhow::Result<()> {
    if response.status.is_success() {
        return Ok(());
    }
    bail!(
        "admin API rejected the request with {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body).trim()
    )
}
