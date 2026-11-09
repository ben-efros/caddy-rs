//! `caddy-rs` command-line interface.
//!
//! Command surface follows Caddy's CLI where it is meaningful for this build: `adapt`, `validate`,
//! `run`, `reload`, `stop`, `list-modules`, `version`. `pki list`/`pki export` and `trust` expose
//! the local CA material persisted by automatic HTTPS (`<data-dir>/pki/authorities/<id>/`); see
//! `docs/compatibility/CADDYFILE.md` for the
//! supported configuration surface.

mod build_info;
mod completion;
mod environ;
mod signals;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};

use caddy_rs_admin::pki::{resolve_data_dir, PkiError, PkiStore, DEFAULT_CA_ID};
use caddy_rs_admin::AdminResponse;
use caddy_rs_config::{AdaptMode, AdaptOptions};
use caddy_rs_core::{Config, GenerationStore, VERSION};
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
    /// Print information about this build.
    BuildInfo,
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
        /// Configuration-acceptance mode (`compatible`, `warn` or `strict`); default compatible.
        #[arg(long, default_value = "compatible", value_name = "MODE")]
        adapt_mode: String,
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
        /// Configuration-acceptance mode (`compatible`, `warn` or `strict`); default compatible.
        #[arg(long, default_value = "compatible", value_name = "MODE")]
        adapt_mode: String,
    },
    /// Run the server with a configuration.
    Run {
        /// Configuration file.
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
        /// Configuration-acceptance mode (`compatible`, `warn` or `strict`); default compatible.
        #[arg(long, default_value = "compatible", value_name = "MODE")]
        adapt_mode: String,
        /// Use saved config, if any (and prefer over --config file).
        #[arg(short = 'r', long)]
        resume: bool,
        /// Autosave file to persist and to load with --resume (default:
        /// `$XDG_CONFIG_HOME/caddy-rs/autosave.json` or `$HOME/.config/caddy-rs/autosave.json`).
        #[arg(long)]
        autosave_path: Option<PathBuf>,
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
    /// Print the environment as seen by this caddy-rs process.
    ///
    /// The output mirrors Caddy's `environ` command: the caddy-rs directory and version fields,
    /// Rust runtime facts, the working directory, a blank line, and then every environment
    /// variable in `KEY=VALUE` form. Go-named fields carry the Rust equivalent: `runtime.Version`
    /// is the rustc version and `runtime.Compiler` is `rustc`.
    ///
    /// If `--envfile` is specified, an environment file with variables in `KEY=VALUE` format is
    /// loaded before printing. Existing process variables are never overwritten.
    Environ {
        /// Environment file(s) to load (repeatable, or comma-separated).
        #[arg(long, value_delimiter = ',')]
        envfile: Vec<PathBuf>,
    },
    /// Generate a shell completion script.
    ///
    /// The supported shells are `bash`, `zsh`, `fish` and `powershell`, matching Caddy's
    /// `completion <shell>` argument shape. Scripts are generated from this binary's clap command
    /// tree, so every compiled subcommand and flag is covered.
    Completion {
        /// Shell to generate completions for (`bash`, `zsh`, `fish` or `powershell`).
        #[arg(value_name = "SHELL")]
        shell: String,
    },
    /// Inspect and export the local certificate authority material.
    Pki {
        #[command(subcommand)]
        command: PkiCommand,
    },
    /// Install the local CA root certificate into the host trust stores.
    Trust {
        /// Data directory containing `pki/authorities` (default: `$CADDY_RS_DATA_DIR` or `.caddy-rs`).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// CA identifier (Caddy's default local CA is `local`).
        #[arg(long, default_value = DEFAULT_CA_ID)]
        ca: String,
        /// Configuration whose `apps.pki` `install_trust` and `storage.root` settings apply.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Config adapter for `--config` (for example `caddyfile`).
        #[arg(long)]
        adapter: Option<String>,
        /// Print the exact commands and paths without modifying any trust store.
        #[arg(long)]
        dry_run: bool,
    },
}

/// `pki` subcommands.
#[derive(Debug, Subcommand)]
enum PkiCommand {
    /// List the local certificate authorities provisioned in the data directory.
    List {
        /// Data directory containing `pki/authorities` (default: `$CADDY_RS_DATA_DIR` or `.caddy-rs`).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Export one CA certificate (root by default) as PEM to stdout.
    Export {
        /// CA identifier (for example `local`).
        id: String,
        /// Data directory containing `pki/authorities` (default: `$CADDY_RS_DATA_DIR` or `.caddy-rs`).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Export the root certificate (default).
        #[arg(long, conflicts_with_all = ["intermediate", "chain"])]
        root: bool,
        /// Export the intermediate certificate chain only.
        #[arg(long, conflicts_with = "chain")]
        intermediate: bool,
        /// Export the full chain: intermediate(s) first, root last (Caddy's `/certificates` order).
        #[arg(long)]
        chain: bool,
    },
}

/// The module registry for the compiled profile.
///
/// `--no-default-features --features minimal` builds the minimal profile (ADR-0008), whose registry
/// omits every module the profile does not compile: proxying, authentication, templates, encoding,
/// rate limiting and variable maps fail closed at configuration load instead of silently working.
fn builtin_module_registry() -> caddy_rs_core::ModuleRegistry {
    caddy_rs_core::ModuleRegistry::builtin_for_profile(cfg!(feature = "minimal"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            match core_error_code(&error) {
                Some(code) => eprintln!("caddy-rs: error[{code}]: {error:#}"),
                None => eprintln!("caddy-rs: error: {error:#}"),
            }
            ExitCode::FAILURE
        }
    }
}

/// The stable, machine-readable code of the first [`caddy_rs_core::Error`] in the chain, if any.
///
/// The code is what scripts and editors match on (`error[module.unknown]`), so it must survive
/// message rewording; see [`caddy_rs_core::Error::code`]. Errors that do not originate in the
/// configuration/validation layer (I/O, TLS, runtime) keep the plain `error:` form.
fn core_error_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<caddy_rs_core::Error>())
        .map(caddy_rs_core::Error::code)
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
        Command::BuildInfo => {
            build_info::print(builtin_module_registry().modules().count());
        }
        Command::ListModules { json } => {
            let registry = builtin_module_registry();
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
            adapt_mode,
            pretty,
            output,
        } => {
            let options = adapt_options(&adapt_mode)?;
            let (json, warnings) = adapt(&config, adapter.as_deref(), options)?;
            let json = if pretty {
                let value: serde_json::Value = serde_json::from_slice(&json)
                    .context("cannot parse adapted JSON for pretty printing")?;
                serde_json::to_vec_pretty(&value)
                    .context("cannot serialize adapted configuration")?
            } else {
                json
            };
            for warning in &warnings {
                eprintln!("warning: {warning}");
            }
            match output {
                Some(path) => std::fs::write(&path, &json)
                    .with_context(|| format!("cannot write output `{}`", path.display()))?,
                None => println!("{}", String::from_utf8_lossy(&json)),
            }
        }
        Command::Validate {
            config,
            adapter,
            adapt_mode,
        } => {
            let options = adapt_options(&adapt_mode)?;
            let loaded = load_validated(&config, adapter.as_deref(), options)?;
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            // Caddy's `validate` provisions the apps, so handler/matcher modules, listener
            // wrappers and routers are constructed before success is reported. Build the same
            // serving generation here (without binding sockets or obtaining certificates) so a
            // configuration cannot validate and then fail at `run`.
            let store = std::sync::Arc::new(GenerationStore::new(std::sync::Arc::new(
                builtin_module_registry(),
            )));
            store
                .load(loaded.model)
                .context("cannot activate configuration")?;
            let runtime = ServerRuntime::new(store);
            runtime
                .validate_provisioning()
                .context("cannot provision configuration")?;
            println!("Valid configuration");
        }
        Command::Run {
            config,
            adapter,
            adapt_mode,
            resume,
            autosave_path,
        } => {
            let options = adapt_options(&adapt_mode)?;
            // Caddy's autosave path: the `--autosave-path` flag wins, then the environment-derived
            // default (`$XDG_CONFIG_HOME/caddy-rs/autosave.json`, `$HOME/.config/caddy-rs/...`,
            // `./.caddy-rs/...`); see `caddy_rs_core::autosave`.
            let autosave_path =
                autosave_path.unwrap_or_else(caddy_rs_core::autosave::default_autosave_path);
            // Publish the path to the admin API this process starts, so admin-driven config
            // changes (`POST /load`, `/config/...`) autosave to the very same file, like Caddy.
            std::env::set_var(caddy_rs_admin::AUTOSAVE_PATH_ENV, &autosave_path);

            // Caddy's run precedence: `--resume` loads the last autosave when one exists,
            // preferring it over `--config` (with a warning); a missing autosave file is not an
            // error and falls back to normal config loading (see cmd/commandfuncs.go runCmd).
            let loaded = if resume {
                match caddy_rs_core::autosave::load_autosave(&autosave_path) {
                    Ok(Some(bytes)) => {
                        if config.is_some() {
                            eprintln!(
                                "caddy-rs: warning: --config and --resume flags were used \
                                 together; ignoring --config and resuming from last configuration \
                                 (autosave `{}`)",
                                autosave_path.display()
                            );
                        } else {
                            eprintln!(
                                "caddy-rs: resuming from last configuration (autosave `{}`)",
                                autosave_path.display()
                            );
                        }
                        Some(LoadedConfig::from_autosave(bytes, &autosave_path)?)
                    }
                    Ok(None) => {
                        eprintln!(
                            "caddy-rs: no autosave file exists (autosave `{}`); loading --config",
                            autosave_path.display()
                        );
                        None
                    }
                    Err(error) => {
                        return Err(anyhow!(
                            "cannot read autosave file `{}`: {error}",
                            autosave_path.display()
                        ))
                    }
                }
            } else {
                None
            };
            let loaded = match loaded {
                Some(loaded) => loaded,
                None => match config {
                    Some(path) => load_validated(&path, adapter.as_deref(), options)?,
                    None => bail!(
                        "no configuration to load: pass --config <path> or use --resume with an \
                         existing autosave file"
                    ),
                },
            };
            let LoadedConfig {
                model,
                warnings,
                json,
            } = loaded;
            // Caddy gates autosave on `admin.config.persist`: an explicit false means the
            // operator does not want the (secret-bearing) config written to disk. Compute it
            // before the model moves into the generation store.
            let persist_config = model
                .admin
                .as_ref()
                .map(|admin| admin.persist_config())
                .unwrap_or(true);
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            let store = Arc::new(GenerationStore::new(Arc::new(builtin_module_registry())));
            let activated = store.load(model).context("cannot activate configuration")?;
            let mut runtime = ServerRuntime::new(Arc::clone(&store));
            let status = runtime.apply().await.context("cannot start listeners")?;
            if persist_config {
                // Caddy autosaves the exact bytes of the successfully loaded config after the
                // config transition completes (caddy.go, unsyncedDecodeAndRun); a failure to
                // autosave is logged but never aborts the server.
                match caddy_rs_core::autosave::autosave(&json, &autosave_path) {
                    Ok(()) => eprintln!(
                        "caddy-rs: autosaved config (load with --resume flag) `{}`",
                        autosave_path.display()
                    ),
                    Err(error) => eprintln!(
                        "caddy-rs: unable to autosave config `{}`: {error}",
                        autosave_path.display()
                    ),
                }
            } else {
                eprintln!(
                    "caddy-rs: config persistence disabled (admin.config.persist=false); \
                     not autosaving `{}`",
                    autosave_path.display()
                );
            }
            eprintln!(
                "caddy-rs: configuration active (generation {})",
                activated.generation.id()
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
            let channels = signals::shutdown_channels()?;
            runtime
                .run_with_force(channels.shutdown, channels.force)
                .await
                .context("runtime failed")?;
        }
        Command::Reload {
            config,
            adapter,
            admin,
        } => {
            let loaded = load_validated(&config, adapter.as_deref(), AdaptOptions::default())?;
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            let body = loaded
                .model
                .to_vec()
                .context("cannot encode configuration")?;
            let response = admin_request(&admin, "POST", "/load", Bytes::from(body)).await?;
            ensure_admin_success(&response)?;
            eprintln!("configuration reloaded");
        }
        Command::Stop { admin } => {
            let response = admin_request(&admin, "POST", "/stop", Bytes::new()).await?;
            ensure_admin_success(&response)?;
            eprintln!("server stopped");
        }
        Command::Environ { envfile } => {
            environ::run(&envfile)?;
        }
        Command::Completion { shell } => {
            print!("{}", completion::generate(&shell)?);
        }
        Command::Pki { command } => run_pki(command).await?,
        Command::Trust {
            data_dir,
            ca,
            config,
            adapter,
            dry_run,
        } => run_trust(data_dir, &ca, config, adapter, dry_run).await?,
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

/// A loaded, validated configuration together with the *exact* JSON bytes that produced it — the
/// bytes Caddy's autosave persists (the raw loaded document for the JSON adapter, the adapter
/// output for the Caddyfile adapter) and `--resume` loads back.
struct LoadedConfig {
    model: Config,
    warnings: Vec<String>,
    /// The exact bytes of the successfully loaded/adapted config JSON.
    json: Vec<u8>,
}

impl LoadedConfig {
    /// Parse and validate autosave bytes (always Caddy JSON, no adapter involved).
    fn from_autosave(bytes: Vec<u8>, path: &Path) -> anyhow::Result<Self> {
        let model = Config::from_slice(&bytes).with_context(|| {
            format!(
                "autosave `{}` does not match the configuration model",
                path.display()
            )
        })?;
        let registry = builtin_module_registry();
        caddy_rs_core::validate_config(&model, &registry).with_context(|| {
            format!("autosave `{}` is not a valid configuration", path.display())
        })?;
        Ok(Self {
            model,
            warnings: Vec::new(),
            json: bytes,
        })
    }
}

/// Parse the `--adapt-mode` flag into adapter options, rejecting unknown mode names with the
/// three accepted values.
fn adapt_options(value: &str) -> anyhow::Result<AdaptOptions> {
    let mode = value.parse::<AdaptMode>().map_err(|message| {
        // There is no configuration file to point at, so the flag itself is the location.
        anyhow::Error::new(caddy_rs_core::Error::invalid("--adapt-mode", message))
    })?;
    Ok(AdaptOptions::new(mode))
}

/// Read `config` and adapt it to Caddy JSON, returning the exact JSON bytes of the loaded/adapted
/// config plus any adapter warnings. For the JSON adapter the bytes are the file contents verbatim
/// (Caddy autosaves the exact bytes it loaded); for the Caddyfile adapter they are the adapter's
/// JSON output.
fn adapt(
    config: &Path,
    adapter: Option<&str>,
    options: AdaptOptions,
) -> anyhow::Result<(Vec<u8>, Vec<String>)> {
    let input = std::fs::read(config)
        .with_context(|| format!("cannot read config `{}`", config.display()))?;
    match infer_adapter(config, adapter).as_deref() {
        Some("caddyfile") => {
            let text = std::str::from_utf8(&input)
                .with_context(|| format!("`{}` is not valid UTF-8", config.display()))?;
            let adapted = caddy_rs_config::adapt_with_options(text, Some(config), options)
                .with_context(|| format!("cannot adapt `{}`", config.display()))?;
            let json = serde_json::to_vec(&adapted.config)
                .context("cannot serialize adapted configuration")?;
            Ok((json, adapted.warnings))
        }
        Some("json") | None => {
            serde_json::from_slice::<serde_json::Value>(&input)
                .with_context(|| format!("`{}` is not valid JSON", config.display()))?;
            Ok((input, Vec::new()))
        }
        Some(other) => {
            bail!("unsupported adapter `{other}`; supported adapters are caddyfile and json")
        }
    }
}

fn load_validated(
    config: &Path,
    adapter: Option<&str>,
    options: AdaptOptions,
) -> anyhow::Result<LoadedConfig> {
    let (json, warnings) = adapt(config, adapter, options)?;
    let model = Config::from_slice(&json).with_context(|| {
        format!(
            "`{}` does not match the configuration model",
            config.display()
        )
    })?;
    let registry = builtin_module_registry();
    caddy_rs_core::validate_config(&model, &registry)
        .with_context(|| format!("`{}` is not a valid configuration", config.display()))?;
    Ok(LoadedConfig {
        model,
        warnings,
        json,
    })
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

// -------------------------------------------------------------------------------------------------
// PKI and trust commands
// -------------------------------------------------------------------------------------------------

/// Resolve the data directory for CLI commands: `--data-dir`, then `$CADDY_RS_DATA_DIR`, then the
/// server runtime's default (`.caddy-rs`). The CLI has no configuration file in this path, so the
/// config `storage.root` fallback cannot apply; document `--data-dir` for non-default deployments.
fn cli_data_dir(explicit: Option<PathBuf>) -> PathBuf {
    resolve_data_dir(explicit, None)
}

fn pki_error(error: PkiError) -> anyhow::Error {
    match error.provisioning_hint() {
        Some(hint) => anyhow!("{error}; {hint}"),
        None => anyhow!("{error}"),
    }
}

async fn run_pki(command: PkiCommand) -> anyhow::Result<()> {
    match command {
        PkiCommand::List { data_dir, json } => {
            let store = PkiStore::new(cli_data_dir(data_dir));
            let authorities = store.list().await.map_err(pki_error)?;
            if json {
                let value = serde_json::json!({
                    "data_dir": store.data_dir().to_string_lossy(),
                    "authorities_dir": store.authorities_dir().to_string_lossy(),
                    "authorities": authorities
                        .iter()
                        .map(|summary| serde_json::json!({
                            "id": summary.id,
                            "directory": summary.directory.to_string_lossy(),
                            "root_common_name": summary.root_common_name,
                            "intermediate_common_name": summary.intermediate_common_name,
                            "root_not_after": summary.root_not_after,
                            "intermediate_not_after": summary.intermediate_not_after,
                            "has_intermediate": summary.has_intermediate,
                        }))
                        .collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }
            if authorities.is_empty() {
                println!(
                    "no local certificate authorities under `{}`",
                    store.authorities_dir().display()
                );
                return Ok(());
            }
            let mut rows: Vec<[String; 5]> = vec![[
                "ID".to_string(),
                "ROOT_CN".to_string(),
                "INTERMEDIATE_CN".to_string(),
                "ROOT_EXPIRES".to_string(),
                "INTERMEDIATE_EXPIRES".to_string(),
            ]];
            for summary in &authorities {
                rows.push([
                    summary.id.clone(),
                    summary
                        .root_common_name
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                    summary
                        .intermediate_common_name
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                    summary
                        .root_not_after
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                    summary
                        .intermediate_not_after
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ]);
            }
            // Column widths follow the data (real Caddy CNs are much longer than the headers).
            let mut widths = [0usize; 5];
            for row in &rows {
                for (index, cell) in row.iter().enumerate() {
                    widths[index] = widths[index].max(cell.chars().count());
                }
            }
            for row in &rows {
                println!(
                    "{:<id_width$} {:<root_width$} {:<intermediate_width$} {:<root_expires_width$} {:<intermediate_expires_width$}",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    id_width = widths[0],
                    root_width = widths[1],
                    intermediate_width = widths[2],
                    root_expires_width = widths[3],
                    intermediate_expires_width = widths[4],
                );
            }
        }
        PkiCommand::Export {
            id,
            data_dir,
            root: _,
            intermediate,
            chain,
        } => {
            let store = PkiStore::new(cli_data_dir(data_dir));
            let ca = store.load(&id).await.map_err(pki_error)?;
            let pem = if chain {
                ca.chain_pem()
            } else if intermediate {
                let pem = ca.intermediate_pem();
                if pem.is_empty() {
                    bail!("CA `{id}` has no intermediate certificate");
                }
                pem
            } else {
                // Root is the default export (it is the certificate `trust` installs).
                ca.root_pem().to_string()
            };
            // PEM is written verbatim to stdout so it can be piped into other tools.
            print!("{pem}");
        }
    }
    Ok(())
}

/// Install the local CA root certificate into the host trust stores.
///
/// Caddy's `caddy trust` fetches the CA through the admin API and installs through
/// `smallstep/truststore` (platform store plus Firefox/NSS and Java). caddy-rs works directly from
/// the data directory instead (no running server required) and plans every store in
/// [`caddy_rs_admin::trust`]: the platform store, each discovered NSS/Firefox database and each
/// discovered Java `cacerts` keystore. Stores whose tool is missing are reported loudly with the
/// documented limitation; unsupported platforms fail with their named limitation. `--dry-run`
/// prints the exact commands without changing anything.
///
/// When `--config` names a configuration, the CA's `install_trust: false`
/// (`apps.pki.certificate_authorities.<id>.install_trust`) is honoured as a no-op with Caddy's
/// "installation disabled" message, and the configured `storage.root` is used for the data
/// directory (matching the server's storage resolution).
async fn run_trust(
    data_dir: Option<PathBuf>,
    ca_id: &str,
    config_path: Option<PathBuf>,
    adapter: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let loaded = match &config_path {
        Some(path) => Some(load_validated(
            path,
            adapter.as_deref(),
            AdaptOptions::default(),
        )?),
        None => None,
    };
    let storage_root = loaded.as_ref().and_then(|loaded| {
        loaded
            .model
            .storage()
            .and_then(|storage| storage.root())
            .map(PathBuf::from)
    });
    if let Some(loaded) = &loaded {
        if let Some(message) = trust_installation_disabled(&loaded.model, ca_id) {
            eprintln!("caddy-rs: {message}");
            return Ok(());
        }
    }

    let store = PkiStore::new(resolve_data_dir(data_dir, storage_root));
    let ca = store.load(ca_id).await.map_err(pki_error)?;
    let environment = caddy_rs_admin::trust::TrustEnvironment::detect();
    let plan = caddy_rs_admin::trust::TrustPlan::detect(
        ca.id(),
        ca.directory().join("root.crt"),
        &environment,
    );

    if dry_run {
        println!("CA id: {}", ca.id());
        println!("root certificate: {}", plan.root_path.display());
        if let Some(common_name) = ca.root_common_name() {
            println!("root common name: {common_name}");
        }
        println!("trust stores:");
        for target in &plan.targets {
            match &target.status {
                caddy_rs_admin::trust::TrustStatus::Ready => {
                    println!("  {}: ready", target.kind.label());
                    for command in &target.commands {
                        println!("    {command}");
                    }
                }
                status => {
                    println!("  {}: not installed", target.kind.label());
                    if let Some(limitation) = status.limitation() {
                        println!("    limitation: {limitation}");
                    }
                }
            }
        }
        println!("no changes made (--dry-run)");
        let commands: Vec<&str> = plan
            .targets
            .iter()
            .flat_map(|target| target.commands.iter().map(String::as_str))
            .collect();
        if !commands.is_empty() {
            println!("to install manually, run:");
            for command in commands {
                println!("  {command}");
            }
        }
        return Ok(());
    }

    eprintln!(
        "caddy-rs: installing root certificate for CA `{}` from `{}`",
        ca.id(),
        plan.root_path.display()
    );
    let report = plan.execute()?;
    for kind in &report.installed {
        eprintln!("caddy-rs: installed root certificate into {}", kind.label());
    }
    for kind in &report.already_installed {
        eprintln!(
            "caddy-rs: root certificate already trusted by {} (no changes)",
            kind.label()
        );
    }
    for (kind, limitation) in &report.skipped {
        eprintln!("caddy-rs: warning: {kind:?} {}: {limitation}", kind.label());
    }
    for (kind, failure) in &report.failures {
        eprintln!("caddy-rs: warning: {} not updated: {failure}", kind.label());
    }
    if !report.any_trusted() {
        let mut reasons: Vec<String> = report
            .skipped
            .iter()
            .map(|(_, limitation)| limitation.clone())
            .chain(report.failures.iter().map(|(_, failure)| failure.clone()))
            .collect();
        if reasons.is_empty() {
            reasons.push("no installable trust store was found on this host".to_string());
        }
        anyhow::bail!(
            "no trust store could be updated: {}; re-run with `--dry-run` to print the manual \
             instructions",
            reasons.join("; ")
        );
    }
    eprintln!(
        "caddy-rs: installed CA `{}` root certificate; restart browsers and Java applications to \
         pick it up",
        ca.id()
    );
    Ok(())
}

/// Caddy's `apps.pki.certificate_authorities.<id>.install_trust: false` message, if configured.
///
/// Caddy logs this while starting the PKI app and skips `installRoot`; the CLI honours the same
/// setting when a config is supplied, so `caddy-rs trust --config ...` never silently installs a
/// CA whose configuration disables trust installation.
fn trust_installation_disabled(config: &Config, ca_id: &str) -> Option<String> {
    let ca = config
        .pki()
        .and_then(|pki| pki.certificate_authorities.as_ref())
        .and_then(|authorities| authorities.get(ca_id))?;
    if ca.install_trust != Some(false) {
        return None;
    }
    Some(format!(
        "root certificate trust store installation disabled by \
         apps.pki.certificate_authorities.{ca_id}.install_trust: false; unconfigured clients may \
         show warnings (no changes made)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn install_trust_false_is_reported_as_a_disabled_no_op() {
        let config = Config::from_value(json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"install_trust": false}
            }}}
        }))
        .expect("config");
        let message = trust_installation_disabled(&config, "local").expect("disabled message");
        assert!(message.contains("install_trust: false"), "{message}");
        assert!(message.contains("no changes made"), "{message}");
        assert!(
            message.contains("unconfigured clients may show warnings"),
            "{message}"
        );
        // Default is install-trust enabled (Caddy's default), and other CAs are unaffected.
        let config = Config::from_value(json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"install_trust": true},
                "staging": {"install_trust": false}
            }}}
        }))
        .expect("config");
        assert_eq!(trust_installation_disabled(&config, "local"), None);
        assert!(trust_installation_disabled(&config, "staging").is_some());
    }

    #[test]
    fn trust_verb_plans_the_platform_store_and_reports_missing_tools_loudly() {
        let directory = std::env::temp_dir().join(format!(
            "caddy-rs-cli-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let root = directory.join("root.crt");
        std::fs::write(
            &root,
            "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let environment = caddy_rs_admin::trust::TrustEnvironment::new(
            caddy_rs_admin::trust::TrustPlatform::Linux,
            None,
            Vec::new(),
        )
        .with_platform_prefix(&directory);
        let plan = caddy_rs_admin::trust::TrustPlan::detect("local", &root, &environment);
        assert!(plan.targets[0].status.limitation().is_some());
        assert!(plan.targets[0]
            .status
            .limitation()
            .unwrap()
            .contains("update-ca-certificates"));
    }
}
