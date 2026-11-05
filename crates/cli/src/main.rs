//! `caddy-rs` command-line interface.
//!
//! Command surface follows Caddy's CLI where it is meaningful for this build: `adapt`, `validate`,
//! `run`, `reload`, `stop`, `list-modules`, `version`. `pki list`/`pki export` and `trust` expose
//! the local CA material persisted by automatic HTTPS (`<data-dir>/pki/authorities/<id>/`); see
//! `docs/compatibility/CADDYFILE.md` and the program repository's compatibility register for the
//! supported configuration surface.

mod signals;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};

use caddy_rs_admin::pki::{resolve_data_dir, CaMaterial, PkiError, PkiStore, DEFAULT_CA_ID};
use caddy_rs_admin::AdminResponse;
use caddy_rs_core::{Config, GenerationStore, ModuleRegistry, VERSION};
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
        config: Option<PathBuf>,
        /// Adapter name (`caddyfile` or `json`).
        #[arg(long)]
        adapter: Option<String>,
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
    /// Inspect and export the local certificate authority material.
    Pki {
        #[command(subcommand)]
        command: PkiCommand,
    },
    /// Install the local CA root certificate into the operating system trust store.
    Trust {
        /// Data directory containing `pki/authorities` (default: `$CADDY_RS_DATA_DIR` or `.caddy-rs`).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// CA identifier (Caddy's default local CA is `local`).
        #[arg(long, default_value = DEFAULT_CA_ID)]
        ca: String,
        /// Print the exact commands and paths without modifying the OS trust store.
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
            let (json, warnings) = adapt(&config, adapter.as_deref())?;
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
        Command::Validate { config, adapter } => {
            let loaded = load_validated(&config, adapter.as_deref())?;
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            println!("Valid configuration");
        }
        Command::Run {
            config,
            adapter,
            resume,
            autosave_path,
        } => {
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
                    Some(path) => load_validated(&path, adapter.as_deref())?,
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
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            let store = Arc::new(GenerationStore::new(Arc::new(ModuleRegistry::builtin())));
            let activated = store.load(model).context("cannot activate configuration")?;
            let mut runtime = ServerRuntime::new(Arc::clone(&store));
            let status = runtime.apply().await.context("cannot start listeners")?;
            // Caddy autosaves the exact bytes of the successfully loaded config after the config
            // transition completes (caddy.go, unsyncedDecodeAndRun); a failure to autosave is
            // logged but never aborts the server.
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
            let loaded = load_validated(&config, adapter.as_deref())?;
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
        Command::Pki { command } => run_pki(command).await?,
        Command::Trust {
            data_dir,
            ca,
            dry_run,
        } => run_trust(data_dir, &ca, dry_run).await?,
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
        let registry = ModuleRegistry::builtin();
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

/// Read `config` and adapt it to Caddy JSON, returning the exact JSON bytes of the loaded/adapted
/// config plus any adapter warnings. For the JSON adapter the bytes are the file contents verbatim
/// (Caddy autosaves the exact bytes it loaded); for the Caddyfile adapter they are the adapter's
/// JSON output.
fn adapt(config: &Path, adapter: Option<&str>) -> anyhow::Result<(Vec<u8>, Vec<String>)> {
    let input = std::fs::read(config)
        .with_context(|| format!("cannot read config `{}`", config.display()))?;
    match infer_adapter(config, adapter).as_deref() {
        Some("caddyfile") => {
            let text = std::str::from_utf8(&input)
                .with_context(|| format!("`{}` is not valid UTF-8", config.display()))?;
            let adapted = caddy_rs_config::adapt_with_source(text, Some(config))
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

fn load_validated(config: &Path, adapter: Option<&str>) -> anyhow::Result<LoadedConfig> {
    let (json, warnings) = adapt(config, adapter)?;
    let model = Config::from_slice(&json).with_context(|| {
        format!(
            "`{}` does not match the configuration model",
            config.display()
        )
    })?;
    let registry = ModuleRegistry::builtin();
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

/// Operating-system trust-store handling for `caddy-rs trust`.
///
/// Only the variant for the target OS is constructed by [`current_trust_platform`]; the others are
/// constructed by unit tests (and would be live when cross-compiled).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustPlatform {
    Linux,
    MacOs,
    Windows,
    Unsupported,
}

fn current_trust_platform() -> TrustPlatform {
    #[cfg(target_os = "linux")]
    {
        TrustPlatform::Linux
    }
    #[cfg(target_os = "macos")]
    {
        TrustPlatform::MacOs
    }
    #[cfg(target_os = "windows")]
    {
        TrustPlatform::Windows
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        TrustPlatform::Unsupported
    }
}

/// One concrete installation step (executed only when `--dry-run` is not given).
#[derive(Debug, Clone, PartialEq, Eq)]
enum InstallStep {
    Copy { from: PathBuf, to: PathBuf },
    Run { program: String, args: Vec<String> },
}

/// A platform-specific plan for installing a CA root certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustPlan {
    platform: TrustPlatform,
    source: PathBuf,
    destination: Option<PathBuf>,
    /// Human-readable commands for `--dry-run`/manual installation.
    commands: Vec<String>,
    /// Steps this process performs when installation is requested.
    steps: Vec<InstallStep>,
    /// Why automatic installation is unavailable (platform unsupported).
    unsupported_reason: Option<String>,
}

fn trust_plan(platform: TrustPlatform, ca: &CaMaterial) -> TrustPlan {
    trust_plan_for(platform, ca.id(), &ca.directory().join("root.crt"))
}

fn trust_plan_for(platform: TrustPlatform, ca_id: &str, root_path: &Path) -> TrustPlan {
    let source = root_path.to_path_buf();
    match platform {
        TrustPlatform::Linux => {
            let destination = PathBuf::from(format!(
                "/usr/local/share/ca-certificates/caddy-rs-{ca_id}.crt"
            ));
            TrustPlan {
                platform,
                source: source.clone(),
                destination: Some(destination.clone()),
                commands: vec![
                    format!(
                        "sudo install -m 0644 '{}' '{}'",
                        source.display(),
                        destination.display()
                    ),
                    "sudo update-ca-certificates".to_string(),
                ],
                steps: vec![
                    InstallStep::Copy {
                        from: source,
                        to: destination,
                    },
                    InstallStep::Run {
                        program: "update-ca-certificates".to_string(),
                        args: Vec::new(),
                    },
                ],
                unsupported_reason: None,
            }
        }
        TrustPlatform::MacOs => {
            let destination = PathBuf::from(format!(
                "/Library/Keychains/System.keychain (certificate `{}`)",
                root_path.display()
            ));
            TrustPlan {
                platform,
                source: source.clone(),
                destination: Some(destination),
                commands: vec![format!(
                    "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'",
                    source.display()
                )],
                steps: vec![InstallStep::Run {
                    program: "security".to_string(),
                    args: vec![
                        "add-trusted-cert".to_string(),
                        "-d".to_string(),
                        "-r".to_string(),
                        "trustRoot".to_string(),
                        "-k".to_string(),
                        "/Library/Keychains/System.keychain".to_string(),
                        source.display().to_string(),
                    ],
                }],
                unsupported_reason: None,
            }
        }
        TrustPlatform::Windows => TrustPlan {
            platform,
            source: source.clone(),
            destination: Some(PathBuf::from("CurrentUser\\Root")),
            commands: vec![format!(
                "certutil -addstore -user Root \"{}\"",
                source.display()
            )],
            steps: Vec::new(),
            unsupported_reason: Some(
                "automatic installation on Windows is not implemented; run the printed certutil \
                 command (this build never modifies the OS trust store silently)"
                    .to_string(),
            ),
        },
        TrustPlatform::Unsupported => TrustPlan {
            platform,
            source,
            destination: None,
            commands: Vec::new(),
            steps: Vec::new(),
            unsupported_reason: Some(
                "this build has no trust-store installation support for this operating system; \
                 install the root PEM manually with the platform's certificate tool"
                    .to_string(),
            ),
        },
    }
}

async fn run_trust(data_dir: Option<PathBuf>, ca_id: &str, dry_run: bool) -> anyhow::Result<()> {
    let store = PkiStore::new(cli_data_dir(data_dir));
    let ca = store.load(ca_id).await.map_err(pki_error)?;
    let plan = trust_plan(current_trust_platform(), &ca);

    if dry_run {
        println!("CA id: {}", ca.id());
        println!("root certificate: {}", plan.source.display());
        if let Some(common_name) = ca.root_common_name() {
            println!("root common name: {common_name}");
        }
        if let Some(destination) = &plan.destination {
            println!("trust store destination: {}", destination.display());
        }
        if let Some(reason) = &plan.unsupported_reason {
            println!("automatic installation is not supported: {reason}");
        }
        println!("no changes made (--dry-run)");
        if !plan.commands.is_empty() {
            println!("to install manually, run:");
            for command in &plan.commands {
                println!("  {command}");
            }
        }
        return Ok(());
    }

    if let Some(reason) = &plan.unsupported_reason {
        bail!(
            "cannot install the CA root certificate automatically: {reason}; re-run with \
             `--dry-run` to print the manual instructions"
        );
    }
    eprintln!(
        "caddy-rs: installing root certificate for CA `{}` from `{}`",
        ca.id(),
        plan.source.display()
    );
    for step in &plan.steps {
        match step {
            InstallStep::Copy { from, to } => {
                eprintln!(
                    "caddy-rs: copying `{}` to `{}`",
                    from.display(),
                    to.display()
                );
                if let Some(parent) = to.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!(
                            "cannot create `{}` (run as root or use `--dry-run` for manual \
                             instructions)",
                            parent.display()
                        )
                    })?;
                }
                std::fs::copy(from, to).with_context(|| {
                    format!(
                        "cannot install `{}` to `{}` (run as root or use `--dry-run` for manual \
                         instructions)",
                        from.display(),
                        to.display()
                    )
                })?;
            }
            InstallStep::Run { program, args } => {
                eprintln!("caddy-rs: running `{program} {}`", args.join(" "));
                let output = std::process::Command::new(program)
                    .args(args)
                    .output()
                    .with_context(|| format!("cannot execute `{program}`"))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    bail!(
                        "`{program}` failed with {}: {}{}",
                        output.status,
                        stdout.trim(),
                        stderr.trim()
                    );
                }
            }
        }
    }
    eprintln!(
        "caddy-rs: installed CA `{}` root certificate; restart browsers and Java applications to \
         pick it up",
        ca.id()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_path() -> PathBuf {
        PathBuf::from("/data/pki/authorities/local/root.crt")
    }

    #[test]
    fn linux_trust_plan_installs_into_ca_certificates_and_updates_the_store() {
        let plan = trust_plan_for(TrustPlatform::Linux, "local", &root_path());
        assert_eq!(plan.platform, TrustPlatform::Linux);
        let destination = plan.destination.as_ref().expect("destination");
        assert_eq!(
            destination,
            &PathBuf::from("/usr/local/share/ca-certificates/caddy-rs-local.crt")
        );
        assert!(plan.unsupported_reason.is_none());
        assert!(plan
            .commands
            .iter()
            .any(|command| command.contains("update-ca-certificates")));
        assert!(matches!(plan.steps[0], InstallStep::Copy { .. }));
        assert!(matches!(plan.steps[1], InstallStep::Run { .. }));
    }

    #[test]
    fn macos_trust_plan_uses_the_security_tool() {
        let plan = trust_plan_for(TrustPlatform::MacOs, "staging", &root_path());
        assert!(plan
            .commands
            .iter()
            .any(|command| command.contains("security add-trusted-cert")));
        assert!(matches!(
            &plan.steps[0],
            InstallStep::Run { program, .. } if program == "security"
        ));
    }

    #[test]
    fn unsupported_platform_reports_a_loud_reason_and_no_steps() {
        for platform in [TrustPlatform::Windows, TrustPlatform::Unsupported] {
            let plan = trust_plan_for(platform, "local", &root_path());
            assert!(plan.unsupported_reason.is_some(), "{platform:?}");
            assert!(plan.steps.is_empty(), "{platform:?}");
        }
    }
}
