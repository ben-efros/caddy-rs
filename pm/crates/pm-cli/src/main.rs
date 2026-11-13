//! caddy-rs-pm — proxy manager daemon
//!
//! This binary runs the proxy manager control plane. It owns the PM state, serves the
//! management API, and applies configuration to the caddy-rs data plane via its admin API.
//!
//! The management API is loopback-only by default. Remote access requires explicit
//! `--listen` with a non-loopback address and should be combined with TLS and authentication.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use base64::Engine;
use caddy_rs_authn::{AuthnConfig, AuthnService, JwtSecretSource, MemoryUserStore, UserStore};
use caddy_rs_pm_api::{create_router, ApiState};
use caddy_rs_pm_runtime::{
    ConfigApplyService, ConfigSettings, HttpCaddyAdmin, PmRuntime, RuntimeConfig,
};
use clap::{Parser, Subcommand};
use reqwest::Client;
use sd_notify::NotifyState;
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

/// Systemd unit file path for caddy-rs-pm.
const CADDY_RS_PM_UNIT_PATH: &str = "/etc/systemd/system/caddy-rs-pm.service";

/// Everything the generated systemd unit encodes about the daemon.
///
/// The unit is the durable record of the effective configuration, so every knob has to be listed.
/// Grouping them keeps the call sites readable and prevents two same-typed arguments (there are
/// several) from being silently swapped.
struct PmUnitConfig<'a> {
    binary_path: &'a Path,
    user: &'a str,
    group: &'a str,
    data_dir: &'a Path,
    listen: SocketAddr,
    admin_url: &'a str,
    allow_non_loopback_admin: bool,
    shutdown_timeout: u64,
    no_sd_notify: bool,
    compat: &'a str,
    log_format: &'a str,
    log_level: &'a str,
    allow_symlink_data_dir: bool,
    bootstrap_admin_email: Option<&'a str>,
    /// Where the bootstrap credentials are read from, when they must not appear in the unit.
    ///
    /// The credentials themselves are deliberately absent: they travel through this file, never
    /// through the unit.
    bootstrap_env_file: Option<&'a Path>,
}

impl Default for PmUnitConfig<'static> {
    fn default() -> Self {
        Self {
            binary_path: Path::new("caddy-rs-pm"),
            user: "caddy-rs",
            group: "caddy-rs",
            data_dir: Path::new("/var/lib/caddy-rs"),
            listen: SocketAddr::from(([127, 0, 0, 1], 81)),
            admin_url: "http://127.0.0.1:2019",
            allow_non_loopback_admin: false,
            shutdown_timeout: 30,
            no_sd_notify: false,
            compat: "native",
            log_format: "json",
            log_level: "info",
            allow_symlink_data_dir: false,
            bootstrap_admin_email: None,
            bootstrap_env_file: None,
        }
    }
}

/// Path of the environment file that carries the bootstrap credentials.
///
/// Neither the unit file nor the process arguments may hold a bootstrap password: the unit file is
/// world-readable and `ps` shows every argument to every local user. systemd reads
/// `EnvironmentFile=` as PID 1 before it drops privileges to `User=`, so a root-owned file with mode
/// 0600 is sufficient, and 0600 is what the installer writes.
const CADDY_RS_PM_ENV_PATH: &str = "/etc/caddy-rs-pm.env";

/// Generate the systemd unit file content for caddy-rs-pm.
fn generate_caddy_rs_pm_unit(config: &PmUnitConfig<'_>) -> String {
    let PmUnitConfig {
        binary_path,
        user,
        group,
        data_dir,
        listen,
        admin_url,
        allow_non_loopback_admin,
        shutdown_timeout,
        no_sd_notify,
        compat,
        log_format,
        log_level,
        allow_symlink_data_dir,
        bootstrap_admin_email,
        bootstrap_env_file,
        ..
    } = *config;

    // Global options belong to the top-level command, so they have to precede the subcommand.
    // `caddy-rs-pm serve --data-dir ...` is rejected by clap with "unexpected argument", which
    // systemd reports as a failed start, so the order below is load-bearing.
    let mut exec_start = format!("ExecStart={}", binary_path.display());
    exec_start.push_str(&format!(" --data-dir {}", data_dir.display()));
    if allow_symlink_data_dir {
        exec_start.push_str(" --allow-symlink-data-dir");
    }
    exec_start.push_str(&format!(" --compat {}", compat));
    exec_start.push_str(&format!(" --log-format {}", log_format));
    exec_start.push_str(&format!(" --log-level {}", log_level));
    if let Some(email) = bootstrap_admin_email {
        exec_start.push_str(&format!(" --bootstrap-admin-email {}", email));
    }
    exec_start.push_str(" serve");
    exec_start.push_str(&format!(" --listen {}", listen));
    exec_start.push_str(&format!(" --admin-url {}", admin_url));
    if allow_non_loopback_admin {
        exec_start.push_str(" --allow-non-loopback-admin");
    }
    exec_start.push_str(&format!(" --shutdown-timeout {}", shutdown_timeout));
    if no_sd_notify {
        exec_start.push_str(" --no-sd-notify");
    }

    // `Type=notify` only works when the daemon actually sends READY=1. With `--no-sd-notify` it
    // never does, and systemd would wait out `TimeoutStartSec` and fail the start.
    let service_type = if no_sd_notify { "simple" } else { "notify" };

    // `-` makes a missing file non-fatal, so a plain install without bootstrap credentials starts.
    let env_file_line = match bootstrap_env_file {
        Some(path) => format!("\nEnvironmentFile=-{}", path.display()),
        None => String::new(),
    };

    format!(
        r#"[Unit]
Description=caddy-rs proxy manager
Documentation=https://github.com/caddyserver/caddy
After=network.target network-online.target caddy-rs.service
Wants=network-online.target caddy-rs.service

[Service]
Type={service_type}
User={user}
Group={group}
ExecStart={exec_start}
TimeoutStopSec={shutdown_timeout}s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths={data_dir_display}
NoNewPrivileges=true
Environment=PM_DATA_DIR={data_dir_display}
Environment=PM_LISTEN={listen}
Environment=PM_ADMIN_URL={admin_url}
Environment=PM_COMPAT={compat}
Environment=PM_LOG_FORMAT={log_format}
Environment=PM_LOG_LEVEL={log_level}{env_file_line}

[Install]
WantedBy=multi-user.target
"#,
        data_dir_display = data_dir.display()
    )
}

/// Install the systemd unit file.
fn install_pm_unit(unit_path: &Path, content: &str, force: bool) -> anyhow::Result<()> {
    if unit_path.exists() && !force {
        let existing = std::fs::read_to_string(unit_path).with_context(|| {
            format!("failed to read existing unit file {}", unit_path.display())
        })?;
        if existing == content {
            println!(
                "Unit file {} already exists with identical content.",
                unit_path.display()
            );
            return Ok(());
        }
        bail!(
            "Unit file {} already exists with different content. Use --force to overwrite.",
            unit_path.display()
        );
    }

    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(unit_path, content)
        .with_context(|| format!("failed to write unit file {}", unit_path.display()))?;

    println!("Created unit file: {}", unit_path.display());
    println!("Run the following commands to enable and start the service:");
    println!("  systemctl daemon-reload");
    println!("  systemctl enable --now caddy-rs-pm");
    Ok(())
}

/// Write (or remove) the environment file that carries the bootstrap credentials.
///
/// The file is the only place a bootstrap password may live: it is written with mode 0600 and is
/// read by systemd as root, so it never reaches the unit file or the process arguments. Passing no
/// credentials removes a file left behind by an earlier install, because a stale password must not
/// keep working after the operator installed without one.
fn write_bootstrap_env_file(
    path: &Path,
    password: Option<&str>,
    totp: Option<&str>,
) -> anyhow::Result<()> {
    if password.is_none() && totp.is_none() {
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            println!(
                "Removed stale bootstrap environment file: {}",
                path.display()
            );
        }
        return Ok(());
    }

    let mut content = String::from(
        "# Bootstrap credentials for caddy-rs-pm, read by systemd before it drops privileges.\n\
         # Mode 0600: these values must never appear in the unit file or in the process arguments.\n",
    );
    if let Some(password) = password {
        content.push_str(&format!("PM_BOOTSTRAP_ADMIN_PASSWORD={password}\n"));
    }
    if let Some(totp) = totp {
        content.push_str(&format!("PM_BOOTSTRAP_ADMIN_TOTP={totp}\n"));
    }

    write_private_file(path, &content)?;
    println!(
        "Created bootstrap environment file: {} (mode 0600)",
        path.display()
    );
    Ok(())
}

/// Write `content` to `path`, creating the file with mode 0600 and no world-readable window.
#[cfg(unix)]
fn write_private_file(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    // `mode` only applies when the file is created, so an existing file is tightened explicitly
    // below; writing through the same handle keeps the secret out of any second window.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    Ok(())
}

/// Write `content` to `path` on platforms without POSIX modes.
#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    std::fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Uninstall the systemd unit file.
fn uninstall_pm_unit(unit_path: &Path, current_content: &str, force: bool) -> anyhow::Result<()> {
    if !unit_path.exists() {
        println!("Unit file {} does not exist.", unit_path.display());
        return Ok(());
    }

    let existing = std::fs::read_to_string(unit_path)
        .with_context(|| format!("failed to read existing unit file {}", unit_path.display()))?;

    if !force && existing != current_content {
        bail!(
            "Unit file {} content differs from generated content. Use --force to remove anyway.",
            unit_path.display()
        );
    }

    std::fs::remove_file(unit_path)
        .with_context(|| format!("failed to remove unit file {}", unit_path.display()))?;

    println!("Removed unit file: {}", unit_path.display());
    println!("Run 'systemctl daemon-reload' to reload systemd configuration.");
    Ok(())
}

/// CLI entry point.
#[derive(Parser, Debug)]
#[command(name = "caddy-rs-pm", version, about = "caddy-rs proxy manager daemon")]
struct Cli {
    /// Global configuration.
    #[command(flatten)]
    global: GlobalArgs,

    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// Global options shared by all subcommands.
#[derive(Parser, Debug)]
struct GlobalArgs {
    /// Data directory for PM state, secrets and certificates.
    ///
    /// The directory and `<data_dir>/pm` are created with mode 0700 on Unix.
    /// A missing data directory is created; an existing one is checked for writability.
    /// Symlinks are rejected unless `--allow-symlink-data-dir` is set.
    #[arg(long, env = "PM_DATA_DIR", default_value = "/var/lib/caddy-rs")]
    data_dir: PathBuf,

    /// Allow the data directory or `<data_dir>/pm` to be a symlink.
    ///
    /// The symlink target is canonicalized and must be a directory.
    /// This is a compatibility option for legacy layouts; the default is to refuse symlinks.
    #[arg(long, env = "PM_ALLOW_SYMLINK_DATA_DIR")]
    allow_symlink_data_dir: bool,

    /// Compatibility profile: `native` (default) or `npm`.
    ///
    /// The native profile uses the native API schema. The `npm` profile will translate
    /// NPM v2.16 payloads into native types (not yet implemented).
    #[arg(long, env = "PM_COMPAT", default_value = "native", value_parser = ["native", "npm"])]
    compat: String,

    /// Log format: `json` (default) or `text`.
    #[arg(long, env = "PM_LOG_FORMAT", default_value = "json", value_parser = ["json", "text"])]
    log_format: String,

    /// Log level filter (e.g., `info`, `debug`, `trace`).
    #[arg(long, env = "PM_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Bootstrap admin email for unattended first-run setup.
    ///
    /// If set along with PM_BOOTSTRAP_ADMIN_PASSWORD, an initial admin user will be created
    /// automatically on first run if no users exist. Useful for Docker/automation.
    #[arg(long, env = "PM_BOOTSTRAP_ADMIN_EMAIL")]
    bootstrap_admin_email: Option<String>,

    /// Bootstrap admin password for unattended first-run setup.
    ///
    /// Required if PM_BOOTSTRAP_ADMIN_EMAIL is set.
    #[arg(long, env = "PM_BOOTSTRAP_ADMIN_PASSWORD")]
    bootstrap_admin_password: Option<String>,

    /// Optional TOTP code for bootstrap admin (if 2FA desired immediately).
    #[arg(long, env = "PM_BOOTSTRAP_ADMIN_TOTP")]
    bootstrap_admin_totp: Option<String>,
}

/// Subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Start the proxy manager daemon.
    Serve(ServeArgs),

    /// Run a one-shot setup (create initial administrator).
    ///
    /// This is not yet implemented; first-run setup will be handled via the management API.
    Setup,

    /// Print the PM version and embedded caddy-rs version.
    Version,

    /// Create a new user (interactive password prompt).
    ///
    /// Connects to the PM management API to create a user. Password is read interactively
    /// unless provided via --password or PM_CREATE_USER_PASSWORD env var.
    CreateUser {
        /// Username for the new user.
        #[arg(value_name = "USERNAME")]
        username: String,

        /// Password for the new user (if not provided, will prompt interactively).
        #[arg(long, env = "PM_CREATE_USER_PASSWORD")]
        password: Option<String>,

        /// Management API URL (default: http://127.0.0.1:81).
        #[arg(long, env = "PM_URL", default_value = "http://127.0.0.1:81")]
        url: String,

        /// Show verbose output including token expiration.
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Role for the new user: admin, editor or viewer.
        #[arg(long, default_value = "admin", value_parser = ["admin", "editor", "viewer"])]
        role: String,

        /// Administrator username used when the server already has users.
        #[arg(long, env = "PM_ADMIN_USERNAME", default_value = "admin")]
        admin_username: String,

        /// Administrator password used when the server already has users.
        #[arg(long, env = "PM_ADMIN_PASSWORD")]
        admin_password: Option<String>,

        /// Administrator access token (skips the admin login) when the server already has users.
        #[arg(long, env = "PM_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },

    /// Log in as an existing user and output the access token.
    ///
    /// Connects to the PM management API to authenticate. Password is read interactively
    /// unless provided via --password or PM_LOGIN_PASSWORD env var.
    /// Outputs the access token for use in subsequent API calls.
    Login {
        /// Username to log in as.
        #[arg(value_name = "USERNAME")]
        username: String,

        /// Password for the user (if not provided, will prompt interactively).
        #[arg(long, env = "PM_LOGIN_PASSWORD")]
        password: Option<String>,

        /// Management API URL (default: http://127.0.0.1:81).
        #[arg(long, env = "PM_URL", default_value = "http://127.0.0.1:81")]
        url: String,

        /// Show verbose output including token expiration.
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Output only the access token (for scripting).
        #[arg(long)]
        only: bool,
    },

    /// Install caddy-rs-pm as a systemd service.
    ///
    /// This creates a systemd unit file at /etc/systemd/system/caddy-rs-pm.service.
    /// After installation, run `systemctl enable --now caddy-rs-pm` to enable and start the service.
    Install {
        /// Force installation even if a unit file already exists.
        #[arg(long)]
        force: bool,
        /// Path to the caddy-rs-pm binary (default: auto-detect from current executable).
        #[arg(long, env = "PM_BINARY_PATH")]
        binary_path: Option<PathBuf>,
        /// User to run the service as (default: caddy-rs).
        #[arg(long, env = "PM_USER", default_value = "caddy-rs")]
        user: String,
        /// Group to run the service as (default: caddy-rs).
        #[arg(long, env = "PM_GROUP", default_value = "caddy-rs")]
        group: String,
        /// Data directory for the service (default: /var/lib/caddy-rs).
        #[arg(long, env = "PM_DATA_DIR", default_value = "/var/lib/caddy-rs")]
        data_dir: PathBuf,
        /// Address to bind the management API (default: 127.0.0.1:81).
        #[arg(long, env = "PM_LISTEN", default_value = "127.0.0.1:81")]
        listen: SocketAddr,
        /// caddy-rs admin API URL (default: http://127.0.0.1:2019).
        #[arg(long, env = "PM_ADMIN_URL", default_value = "http://127.0.0.1:2019")]
        admin_url: String,
        /// Allow a non-loopback admin URL.
        #[arg(long, env = "PM_ALLOW_NON_LOOPBACK_ADMIN")]
        allow_non_loopback_admin: bool,
        /// Graceful shutdown timeout in seconds (default: 30).
        #[arg(long, env = "PM_SHUTDOWN_TIMEOUT", default_value = "30")]
        shutdown_timeout: u64,
        /// Disable systemd readiness notification.
        #[arg(long, env = "PM_NO_SD_NOTIFY")]
        no_sd_notify: bool,
        /// Compatibility profile: native or npm (default: native).
        #[arg(long, env = "PM_COMPAT", default_value = "native", value_parser = ["native", "npm"])]
        compat: String,
        /// Log format: json or text (default: json).
        #[arg(long, env = "PM_LOG_FORMAT", default_value = "json", value_parser = ["json", "text"])]
        log_format: String,
        /// Log level filter (default: info).
        #[arg(long, env = "PM_LOG_LEVEL", default_value = "info")]
        log_level: String,
        /// Allow the data directory to be a symlink.
        #[arg(long, env = "PM_ALLOW_SYMLINK_DATA_DIR")]
        allow_symlink_data_dir: bool,
    },

    /// Uninstall caddy-rs-pm systemd service.
    ///
    /// This removes the systemd unit file at /etc/systemd/system/caddy-rs-pm.service.
    /// By default, the file is only removed if it matches the current generated content.
    /// Use --force to remove regardless of content mismatch.
    Uninstall {
        /// Force removal even if the unit file content differs from generated content.
        #[arg(long)]
        force: bool,
    },
}

/// Arguments for the `serve` subcommand.
#[derive(Parser, Debug)]
struct ServeArgs {
    /// Address to bind the management API.
    ///
    /// Defaults to loopback only (`127.0.0.1:81`). To allow remote access, explicitly
    /// bind to a non-loopback address (e.g., `0.0.0.0:81`). Remote access requires
    /// TLS and authentication which are not yet implemented; this is a fail-closed boundary.
    #[arg(long, env = "PM_LISTEN", default_value = "127.0.0.1:81")]
    listen: SocketAddr,

    /// caddy-rs admin API URL.
    ///
    /// Must be an HTTP URL on a loopback address (127.0.0.1 or [::1]).
    /// Non-loopback URLs require explicit opt-in via `--allow-non-loopback-admin`.
    #[arg(long, env = "PM_ADMIN_URL", default_value = "http://127.0.0.1:2019")]
    admin_url: String,

    /// Allow a non-loopback admin URL.
    ///
    /// This is unsafe and should only be used in controlled environments where the
    /// admin API is protected by a separate firewall or mTLS.
    #[arg(long, env = "PM_ALLOW_NON_LOOPBACK_ADMIN")]
    allow_non_loopback_admin: bool,

    /// Graceful shutdown timeout in seconds.
    #[arg(long, env = "PM_SHUTDOWN_TIMEOUT", default_value = "30")]
    shutdown_timeout: u64,

    /// Disable systemd readiness notification.
    #[arg(long, env = "PM_NO_SD_NOTIFY")]
    no_sd_notify: bool,
}

/// Application errors.
#[derive(Error, Debug)]
enum CliError {
    #[error("invalid argument: {0}")]
    InvalidArg(String),

    #[error("runtime error: {0}")]
    Runtime(#[from] caddy_rs_pm_runtime::RuntimeError),

    #[error("apply service error: {0}")]
    ApplyService(#[from] caddy_rs_pm_runtime::ApplyError),

    #[error("admin client error: {0}")]
    AdminClient(#[from] caddy_rs_pm_runtime::AdminError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP server error: {0}")]
    HttpServer(#[from] axum::Error),

    #[error("sd_notify error: {0}")]
    SdNotify(String),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("auth error: {0}")]
    Auth(#[from] caddy_rs_authn::AuthError),

    #[error("other error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging.
    init_logging(&cli.global);

    if let Err(err) = run(cli).await {
        error!(%err, "fatal error");
        std::process::exit(1);
    }
}

fn init_logging(global: &GlobalArgs) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&global.log_level));

    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false);

    match global.log_format.as_str() {
        "json" => subscriber.json().init(),
        "text" => subscriber.init(),
        _ => subscriber.init(),
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Serve(args) => serve(cli.global, args).await,
        Command::Setup => {
            info!("setup command not yet implemented; use the management API");
            Ok(())
        }
        Command::Version => {
            println!(
                "caddy-rs-pm {} (caddy-rs {})",
                env!("CARGO_PKG_VERSION"),
                caddy_rs_core::VERSION
            );
            Ok(())
        }
        Command::CreateUser {
            username,
            password,
            url,
            verbose,
            role,
            admin_username,
            admin_password,
            admin_token,
        } => {
            let password = get_password(password, "Password: ").await?;
            create_user(
                &url,
                &username,
                &password,
                &role,
                verbose,
                &admin_username,
                admin_password,
                admin_token,
            )
            .await?;
            Ok(())
        }
        Command::Login {
            username,
            password,
            url,
            verbose,
            only,
        } => {
            let password = get_password(password, "Password: ").await?;
            if let Err(e) = login(&url, &username, &password, verbose, only).await {
                eprintln!("{}", e);
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Install {
            force,
            binary_path,
            user,
            group,
            data_dir,
            listen,
            admin_url,
            allow_non_loopback_admin,
            shutdown_timeout,
            no_sd_notify,
            compat,
            log_format,
            log_level,
            allow_symlink_data_dir,
        } => {
            let binary = binary_path.unwrap_or_else(|| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("caddy-rs-pm"))
            });
            let env_file = Path::new(CADDY_RS_PM_ENV_PATH);
            let has_credentials = cli.global.bootstrap_admin_password.is_some()
                || cli.global.bootstrap_admin_totp.is_some();
            let content = generate_caddy_rs_pm_unit(&PmUnitConfig {
                binary_path: &binary,
                user: &user,
                group: &group,
                data_dir: &data_dir,
                listen,
                admin_url: &admin_url,
                allow_non_loopback_admin,
                shutdown_timeout,
                no_sd_notify,
                compat: &compat,
                log_format: &log_format,
                log_level: &log_level,
                allow_symlink_data_dir,
                bootstrap_admin_email: cli.global.bootstrap_admin_email.as_deref(),
                bootstrap_env_file: has_credentials.then_some(env_file),
            });
            install_pm_unit(Path::new(CADDY_RS_PM_UNIT_PATH), &content, force)?;
            // Written after the unit so a refused unit install leaves nothing behind.
            write_bootstrap_env_file(
                env_file,
                cli.global.bootstrap_admin_password.as_deref(),
                cli.global.bootstrap_admin_totp.as_deref(),
            )?;
            Ok(())
        }
        Command::Uninstall { force } => {
            let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("caddy-rs-pm"));
            // Uninstall compares the installed unit against the *default* unit: it removes the
            // file only when it is byte-identical to what a stock install would have written, so
            // a hand-edited unit is never deleted without `--force`.
            let content = generate_caddy_rs_pm_unit(&PmUnitConfig {
                binary_path: &binary,
                ..PmUnitConfig::default()
            });
            uninstall_pm_unit(Path::new(CADDY_RS_PM_UNIT_PATH), &content, force)?;
            // The unit is gone, so its credentials must not outlive it.
            write_bootstrap_env_file(Path::new(CADDY_RS_PM_ENV_PATH), None, None)?;
            Ok(())
        }
    }
}

async fn serve(global: GlobalArgs, args: ServeArgs) -> Result<(), CliError> {
    info!(
        data_dir = %global.data_dir.display(),
        listen = %args.listen,
        admin_url = %args.admin_url,
        compat = %global.compat,
        "starting caddy-rs-pm"
    );

    // Validate compatibility profile
    if global.compat == "npm" {
        return Err(CliError::InvalidArg(
            "compatibility profile 'npm' is not yet implemented; use 'native' or a different profile. \
             See T-PM-135 for tracking details.".to_string(),
        ));
    }

    // Validate admin URL.
    let admin_url = url::Url::parse(&args.admin_url)?;
    if !args.allow_non_loopback_admin && !is_loopback_url(&admin_url) {
        return Err(CliError::InvalidArg(
            "admin URL must be a loopback address; use --allow-non-loopback-admin to override"
                .to_string(),
        ));
    }

    // Create runtime configuration.
    let mut runtime_config = RuntimeConfig::new(global.data_dir.clone());
    runtime_config = runtime_config.allow_symlink_data_dir(global.allow_symlink_data_dir);

    // Open the PM runtime (data-directory preflight, state layout).
    let runtime = PmRuntime::open(runtime_config)?;
    info!(data_dir = %runtime.config().data_dir.display(), "PM runtime opened");

    // Create admin client for caddy-rs.
    let admin = HttpCaddyAdmin::new(&args.admin_url, args.allow_non_loopback_admin)?;
    info!(admin_url = %args.admin_url, "admin client created");

    // Create config apply service.
    let settings = ConfigSettings::default();
    let applier = ConfigApplyService::new(runtime.clone(), Arc::new(admin), settings);
    info!("config apply service created");

    // Create certificate inventory source (reads from caddy-rs admin).
    let inventory = create_inventory_source(&args.admin_url)?;
    info!("certificate inventory source created");

    // Create authentication service.
    //
    // The JWT signing secret is persisted under the data directory (or supplied by the deployment
    // through `PM_JWT_SECRET`) so that tokens issued before a restart are still accepted
    // afterwards; a per-process random key would log every user out on every restart.
    let env_secret = jwt_secret_from_env()?;
    let jwt_secret_source =
        resolve_jwt_secret_source(&runtime.config().data_dir, env_secret.as_deref())?;
    let env_override = env_secret.is_some();
    let authn_config = AuthnConfig {
        jwt_secret_source,
        ..AuthnConfig::default()
    };
    let authn_store = MemoryUserStore::new();
    let authn = AuthnService::new(authn_store.clone(), authn_config)?;

    // Bootstrap admin user if environment variables are set.
    if let (Some(email), Some(password)) = (
        &global.bootstrap_admin_email,
        &global.bootstrap_admin_password,
    ) {
        info!(email = %email, "checking for bootstrap admin setup");
        // Check if any users exist
        let users = authn_store.list_users().await?;
        if users.is_empty() {
            info!("no users found, creating bootstrap admin user");
            let role = caddy_rs_authn::Role::admin();
            let _user = authn
                .create_user(email.clone(), password, role)
                .await
                .map_err(|e| {
                    CliError::InvalidArg(format!("failed to create bootstrap admin: {}", e))
                })?;

            // If TOTP code provided, verify it
            if let Some(totp_code) = &global.bootstrap_admin_totp {
                authn.totp_verify(_user.id, totp_code).await.map_err(|e| {
                    CliError::InvalidArg(format!("failed to verify bootstrap TOTP: {}", e))
                })?;
                info!("bootstrap admin TOTP configured");
            }

            // The store is in-memory and no endpoint reads it yet, so say that instead of implying
            // a working login: T-PM-125 replaces the store, T-PM-128 adds the endpoints.
            warn!(
                "bootstrap admin created in the in-memory user store; no management endpoint can \
                 use it until T-PM-125 (persistent users) and T-PM-128 (auth endpoints) land"
            );
        } else {
            info!("users already exist, skipping bootstrap admin creation");
        }
    }

    info!(
        env_override,
        "authentication service created with a persisted JWT signing key"
    );

    // Build API state.
    //
    // The API reads the authn service for first-run setup (`POST /auth/setup`), but the endpoints
    // that authenticate a session and authorise a caller are still T-PM-128, and the user store is
    // in-memory until T-PM-125. Mutations therefore stay behind the loopback-only guard in
    // pm-api, and the setup route is guarded the same way, so it cannot be driven remotely.
    let state = ApiState::new(runtime, authn)
        .with_applier(applier)
        .with_inventory(inventory);

    // Build the router.
    let app = create_router(state);

    // Wrap with connect info for loopback mutation guard.
    let app = app.into_make_service_with_connect_info::<SocketAddr>();

    // Bind the management listener.
    let listener = TcpListener::bind(args.listen).await?;
    let local_addr = listener.local_addr()?;
    info!(management_addr = %local_addr, "management API listening");

    // Systemd readiness notification.
    let sd_notify_enabled = !args.no_sd_notify && sd_notify::booted().unwrap_or(false);
    if sd_notify_enabled {
        sd_notify::notify(true, &[NotifyState::Ready])
            .map_err(|e| CliError::SdNotify(e.to_string()))?;
        info!("systemd readiness notification sent");
    }

    // Graceful shutdown. axum stops accepting when this future resolves and then drains in-flight
    // connections; `--shutdown-timeout` bounds that drain so a stuck connection cannot hold the unit
    // in "deactivating" until systemd's TimeoutStopSec kills it.
    let drain_timeout = Duration::from_secs(args.shutdown_timeout);
    let shutdown = async move {
        shutdown_signal().await;
        tokio::spawn(async move {
            tokio::time::sleep(drain_timeout).await;
            warn!(
                timeout_secs = drain_timeout.as_secs(),
                "graceful shutdown timed out; exiting"
            );
            std::process::exit(0);
        });
    };

    // Serve with graceful shutdown.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    info!("management API shut down gracefully");
    Ok(())
}

/// Environment variable that supplies the JWT signing key instead of the key file.
///
/// Deliberately not a clap argument: an option would also be accepted on the command line, where
/// the secret is world-readable in the process table (`ps`, `/proc/<pid>/cmdline`). The daemon only
/// ever reads it from the environment, which the deployment controls (e.g. a 0600 systemd
/// `EnvironmentFile`).
const PM_JWT_SECRET_ENV: &str = "PM_JWT_SECRET";

/// Where the JWT signing key lives, relative to the data directory.
const JWT_SIGNING_KEY_PATH: &str = "auth/signing.key";

/// Read the `PM_JWT_SECRET` override, if any, without exposing its value.
fn jwt_secret_from_env() -> Result<Option<String>, CliError> {
    match std::env::var(PM_JWT_SECRET_ENV) {
        Ok(secret) => Ok(Some(secret)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        // Never echo the value: it is not valid UTF-8 and would end up mangled in a log line.
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::InvalidArg(format!(
            "{PM_JWT_SECRET_ENV} must be valid UTF-8"
        ))),
    }
}

/// Resolve the JWT signing-key source for this boot.
///
/// Precedence: an explicit `PM_JWT_SECRET` wins over the key file, so a deployment can rotate the
/// secret without touching the data directory. Otherwise the key is read from
/// `<data_dir>/auth/signing.key`; the authn crate creates it with mode 0600 on first boot and
/// re-reads the same key on every later boot, which is what keeps existing tokens valid.
///
/// `env_secret` is a parameter rather than a direct `std::env` read so the precedence can be tested
/// without mutating process-global state.
fn resolve_jwt_secret_source(
    data_dir: &Path,
    env_secret: Option<&str>,
) -> Result<JwtSecretSource, CliError> {
    if let Some(secret) = env_secret {
        if secret.is_empty() {
            return Err(CliError::InvalidArg(format!(
                "{PM_JWT_SECRET_ENV} is set but empty; set a non-empty secret or unset it"
            )));
        }
        return Ok(JwtSecretSource::Master(secret.to_string()));
    }

    let path = data_dir.join(JWT_SIGNING_KEY_PATH);
    // `parent()` is always `Some` for a two-component relative path, but fall back rather than
    // unwrap so a future change to the constant cannot panic the daemon at startup.
    create_owner_only_dir(path.parent().unwrap_or(data_dir))?;
    refuse_group_or_world_readable(&path)?;
    Ok(JwtSecretSource::File(path))
}

/// Create `dir` and its parents, owner-only (0700) on Unix.
///
/// The key file itself is 0600, but the directory that holds it must not be traversable either:
/// otherwise a local user can enumerate the data directory.
fn create_owner_only_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Refuse a signing-key file that group or other can read.
///
/// A JWT signing key readable by any local user lets that user mint tokens for any account, so the
/// daemon refuses to start with a located error naming the path and the observed mode instead of
/// silently trusting a misconfigured file (a key restored from a backup, a bad `chmod`). This is a
/// configuration guard, not a defence against an attacker who can already change the file's mode.
#[cfg(unix)]
fn refuse_group_or_world_readable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        // Missing is the normal first-boot case: authn creates the file owner-only.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(CliError::InvalidArg(format!(
                "could not inspect JWT signing key {}: {error}",
                path.display()
            )))
        }
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CliError::InvalidArg(format!(
            "JWT signing key {} has mode 0o{mode:03o}, which is readable by group or other; \
             restrict it to 0600 with `chmod 600 {}` or supply the key via {PM_JWT_SECRET_ENV}",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_group_or_world_readable(_path: &Path) -> Result<(), CliError> {
    // Non-Unix platforms have no POSIX mode bits to check; ACLs are the platform's own concern.
    Ok(())
}

/// Create a certificate inventory source that reads from the caddy-rs admin API.
fn create_inventory_source(
    admin_url: &str,
) -> Result<caddy_rs_pm_api::SharedCertificateInventory, CliError> {
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let base_url = url::Url::parse(admin_url)?.join("/runtime/inventory")?;

    let inventory = CaddyInventorySource { client, base_url };
    Ok(Arc::new(inventory))
}

/// Certificate inventory source that reads from caddy-rs `/runtime/inventory`.
struct CaddyInventorySource {
    client: Client,
    base_url: url::Url,
}

impl caddy_rs_pm_api::CertificateInventorySource for CaddyInventorySource {
    fn list_certificates(
        &self,
    ) -> Result<Vec<caddy_rs_pm_api::CertificateRecord>, caddy_rs_pm_api::InventoryError> {
        // `CertificateInventorySource` is a synchronous trait because the API crate must stay free
        // of a transport. The handler that calls it runs on a tokio worker, and `Handle::block_on`
        // panics on a worker thread ("cannot start a runtime from within a runtime"). Wrapping the
        // call in `block_in_place` hands the worker's remaining tasks to another thread first, which
        // makes blocking here legal on a multi-threaded runtime. `serve` uses `#[tokio::main]`'s
        // multi-threaded runtime, so this is the supported path; a current-thread runtime would
        // panic, and that is why the runtime flavour is pinned rather than inferred.
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|e| caddy_rs_pm_api::InventoryError::new(format!("no tokio runtime: {e}")))?;

        tokio::task::block_in_place(|| {
            handle.block_on(async {
                let resp = self
                    .client
                    .get(self.base_url.clone())
                    .send()
                    .await
                    .map_err(|e| {
                        caddy_rs_pm_api::InventoryError::new(format!("HTTP error: {e}"))
                    })?;

                if !resp.status().is_success() {
                    return Err(caddy_rs_pm_api::InventoryError::new(format!(
                        "unexpected status: {}",
                        resp.status()
                    )));
                }

                let inventory: CaddyRuntimeInventory = resp.json().await.map_err(|e| {
                    caddy_rs_pm_api::InventoryError::new(format!("JSON decode error: {e}"))
                })?;

                // Convert caddy-rs inventory certificates to PM CertificateRecord
                let records = inventory
                    .certificates
                    .into_iter()
                    .map(|cert| {
                        caddy_rs_pm_api::CertificateRecord {
                            domains: if cert.sans.is_empty() {
                                vec![cert.subject.clone()]
                            } else {
                                cert.sans.clone()
                            },
                            sans: cert.sans,
                            issuer: cert.issuer.unwrap_or_else(|| "unknown".to_string()),
                            expires_at_unix: cert.not_after.map(|ts| ts as i64),
                            source: cert.source,
                            renewal_error: None, // caddy-rs inventory doesn't expose renewal error yet
                        }
                    })
                    .collect();

                Ok(records)
            })
        })
    }
}

/// Check if a URL is on a loopback address.
fn is_loopback_url(url: &url::Url) -> bool {
    if let Some(host) = url.host() {
        match host {
            url::Host::Ipv4(addr) => addr.is_loopback(),
            url::Host::Ipv6(addr) => addr.is_loopback(),
            url::Host::Domain(domain) => domain == "localhost",
        }
    } else {
        false
    }
}

/// Wait for shutdown signal (SIGTERM, SIGINT, or systemd stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to listen for SIGTERM");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

/// caddy-rs `/runtime/inventory` response structure.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CaddyRuntimeInventory {
    #[serde(default)]
    generation_id: Option<u64>,
    #[serde(default)]
    admin: Option<serde_json::Value>,
    #[serde(default)]
    listeners: Vec<serde_json::Value>,
    certificates: Vec<CaddyInventoryCertificate>,
    #[serde(default)]
    health_checks: Vec<serde_json::Value>,
}

/// Certificate entry in caddy-rs inventory response.
#[derive(Debug, Deserialize)]
struct CaddyInventoryCertificate {
    subject: String,
    sans: Vec<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    not_after: Option<f64>,
    source: String,
}

/// Response from create-user API.
#[derive(Debug, Deserialize)]
struct CreateUserResponse {
    user_id: String,
    access_token: String,
    refresh_token: String,
}

/// Response from login API.
#[derive(Debug, Deserialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

/// Read password from CLI argument, environment variable, or interactive prompt.
async fn get_password(password_opt: Option<String>, prompt: &str) -> Result<String, CliError> {
    if let Some(pwd) = password_opt {
        return Ok(pwd);
    }

    // Check for common environment variables (handled by clap env = "...")
    // If we get here, we need to prompt interactively
    use std::io::{self, Write};
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    println!();
    Ok(password)
}

/// Create a new user via the PM management API.
///
/// On a fresh install this is the first-run setup: the caller becomes the initial administrator and
/// receives tokens. Once a user exists, setup is closed (it is unauthenticated, so leaving it open
/// would be a takeover path), and the account is created through the authenticated `POST /users`
/// with administrator credentials.
#[allow(clippy::too_many_arguments)]
async fn create_user(
    base_url: &str,
    username: &str,
    password: &str,
    role: &str,
    verbose: bool,
    admin_username: &str,
    admin_password: Option<String>,
    admin_token: Option<String>,
) -> Result<(), CliError> {
    let client = Client::new();
    let base = base_url.trim_end_matches('/');

    let configured = client
        .get(format!("{base}/api/v1/setup"))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?
        .get("configured")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !configured {
        return create_first_admin(&client, base, username, password, verbose).await;
    }

    // The server already has users, so this needs an administrator.
    let token = match admin_token {
        Some(token) => token,
        None => {
            let Some(admin_password) = admin_password else {
                return Err(CliError::InvalidArg(
                    "this server already has users, so creating one requires an administrator: \
                     pass --admin-password (or set PM_ADMIN_PASSWORD), or --admin-token \
                     (PM_ADMIN_TOKEN). On a fresh install no administrator is needed."
                        .to_owned(),
                ));
            };
            login_for_token(&client, base, admin_username, &admin_password).await?
        }
    };

    let response = client
        .post(format!("{base}/api/v1/users"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "role": role,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(CliError::InvalidArg(format!(
            "Failed to create user (HTTP {}): {}",
            status, error_text
        )));
    }

    let created: serde_json::Value = response.json().await?;
    println!("User created successfully!");
    println!(
        "  User ID: {}",
        created.get("id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "  Username: {}",
        created
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or(username)
    );
    println!(
        "  Role: {}",
        created
            .get("role")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(role)
    );
    if verbose {
        println!("  Created by: {admin_username}");
    }
    Ok(())
}

/// First-run setup: create the initial administrator and print its tokens.
async fn create_first_admin(
    client: &Client,
    base: &str,
    username: &str,
    password: &str,
    verbose: bool,
) -> Result<(), CliError> {
    let response = client
        .post(format!("{base}/api/v1/auth/setup"))
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(CliError::InvalidArg(format!(
            "Failed to create user (HTTP {}): {}",
            status, error_text
        )));
    }

    let result: CreateUserResponse = response.json().await?;

    println!("User created successfully!");
    println!("  User ID: {}", result.user_id);
    println!("  Access Token: {}", result.access_token);
    println!("  Refresh Token: {}", result.refresh_token);

    if verbose {
        // Decode token to show expiration (if available)
        if let Ok(claims) = decode_token_claims(&result.access_token) {
            if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
                let exp_time = chrono::DateTime::from_timestamp(exp, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("  Token expires: {}", exp_time);
            }
        }
    }

    Ok(())
}

/// Exchange administrator credentials for an access token.
async fn login_for_token(
    client: &Client,
    base: &str,
    username: &str,
    password: &str,
) -> Result<String, CliError> {
    let response = client
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(CliError::InvalidArg(format!(
            "Administrator login as '{username}' failed (HTTP {}): {}. Use --admin-username if \
             the administrator has a different name.",
            status, error_text
        )));
    }

    let tokens: serde_json::Value = response.json().await?;
    tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| CliError::InvalidArg("login response carried no access token".to_owned()))
}

/// Log in as an existing user via the PM management API.
async fn login(
    base_url: &str,
    username: &str,
    password: &str,
    verbose: bool,
    only: bool,
) -> Result<(), CliError> {
    let client = Client::new();
    let url = format!("{}/api/v1/auth/login", base_url.trim_end_matches('/'));

    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(CliError::InvalidArg(format!(
            "Failed to login (HTTP {}): {}",
            status, error_text
        )));
    }

    let result: LoginResponse = response.json().await?;

    if only {
        println!("{}", result.access_token);
    } else {
        println!("Login successful!");
        println!("Access Token: {}", result.access_token);
        println!("Refresh Token: {}", result.refresh_token);

        if verbose {
            // Decode token to show expiration (if available)
            if let Ok(claims) = decode_token_claims(&result.access_token) {
                if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
                    let exp_time = chrono::DateTime::from_timestamp(exp, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!("Token expires: {}", exp_time);
                }
            }
        }
    }

    Ok(())
}

/// Decode JWT token claims (without verification) to extract expiration info.
fn decode_token_claims(token: &str) -> Result<serde_json::Value, CliError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(CliError::InvalidArg("Invalid token format".to_string()));
    }

    // JWT payload is the second part, base64url encoded
    let payload = parts[1];
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("Failed to decode token payload")?;

    let claims: serde_json::Value =
        serde_json::from_slice(&decoded).context("Failed to parse token claims")?;

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argv a generated unit passes to the daemon, without the binary path.
    fn exec_start_args(unit: &str) -> Vec<String> {
        let line = unit
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("the generated unit has an ExecStart line");
        let mut argv: Vec<String> = line["ExecStart=".len()..]
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        argv.remove(0);
        argv
    }

    #[test]
    fn the_generated_unit_starts_the_daemon_it_describes() {
        // The unit is the only thing that starts the daemon in production, so it has to parse as a
        // valid invocation of this very binary. Global options belong to the top-level command:
        // placed after `serve` they make clap exit 2 and systemd reports a failed start.
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig {
            binary_path: Path::new("/usr/local/bin/caddy-rs-pm"),
            bootstrap_admin_email: Some("admin@example.com"),
            ..PmUnitConfig::default()
        });
        let argv = std::iter::once("caddy-rs-pm".to_string()).chain(exec_start_args(&unit));
        let cli = Cli::try_parse_from(argv)
            .expect("the generated ExecStart must parse as a caddy-rs-pm invocation");
        assert!(
            matches!(cli.command, Command::Serve(_)),
            "the unit must start the serve subcommand"
        );
        assert_eq!(cli.global.data_dir, PathBuf::from("/var/lib/caddy-rs"));
        assert_eq!(cli.global.log_level, "info");
        assert_eq!(
            cli.global.bootstrap_admin_email.as_deref(),
            Some("admin@example.com")
        );
    }

    #[test]
    fn the_unit_waits_for_ready_only_when_the_daemon_notifies() {
        // `Type=notify` with `--no-sd-notify` never receives READY=1 and systemd fails the start
        // after TimeoutStartSec, so the two have to agree.
        let notifying = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        assert!(notifying.contains("\nType=notify\n"));
        assert!(!notifying.contains("--no-sd-notify"));

        let quiet = generate_caddy_rs_pm_unit(&PmUnitConfig {
            no_sd_notify: true,
            ..PmUnitConfig::default()
        });
        assert!(quiet.contains("\nType=simple\n"));
        assert!(quiet.contains("--no-sd-notify"));
    }

    #[test]
    fn the_unit_advertises_no_reload_because_the_daemon_has_no_sighup_handler() {
        // `shutdown_signal` waits for SIGINT and SIGTERM only, so a SIGHUP terminates the process.
        // Advertising ExecReload would make `systemctl reload` kill the daemon.
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        assert!(!unit.contains("ExecReload"));
        assert!(!unit.contains("HUP"));
    }

    #[test]
    fn bootstrap_secrets_never_reach_the_unit_file() {
        // The unit file is world-readable and the unit's arguments are visible in `ps`; a bootstrap
        // password may only travel through the 0600 environment file.
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig {
            bootstrap_env_file: Some(Path::new(CADDY_RS_PM_ENV_PATH)),
            ..PmUnitConfig::default()
        });
        // There is no way to put a credential in the unit: the generator takes no secret at all,
        // and the only credential channel it knows is the 0600 environment file.
        assert!(!unit.contains("--bootstrap-admin-password"));
        assert!(!unit.contains("--bootstrap-admin-totp"));
        assert!(unit.contains(&format!("EnvironmentFile=-{CADDY_RS_PM_ENV_PATH}")));
    }

    #[test]
    fn a_plain_install_references_no_environment_file() {
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        assert!(!unit.contains("EnvironmentFile"));
    }

    #[cfg(unix)]
    #[test]
    fn the_bootstrap_environment_file_is_owner_only_and_removed_when_unused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("caddy-rs-pm-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the test directory");
        let path = dir.join("caddy-rs-pm.env");

        write_bootstrap_env_file(&path, Some("hunter2"), Some("123456"))
            .expect("write the environment file");
        let mode = std::fs::metadata(&path)
            .expect("the environment file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a file carrying a password must be owner-only");
        let content = std::fs::read_to_string(&path).expect("read the environment file");
        assert!(content.contains("PM_BOOTSTRAP_ADMIN_PASSWORD=hunter2"));
        assert!(content.contains("PM_BOOTSTRAP_ADMIN_TOTP=123456"));

        // Installing without credentials must not leave a stale password behind.
        write_bootstrap_env_file(&path, None, None).expect("remove the environment file");
        assert!(!path.exists(), "a stale credentials file must be removed");

        std::fs::remove_dir_all(&dir).expect("remove the test directory");
    }

    /// Boot the authentication service the way `serve` does, against `data_dir`.
    async fn boot_authn(data_dir: &Path, store: MemoryUserStore) -> AuthnService<MemoryUserStore> {
        let source = resolve_jwt_secret_source(data_dir, None).expect("resolve the signing key");
        AuthnService::new(
            store,
            AuthnConfig {
                jwt_secret_source: source,
                ..AuthnConfig::default()
            },
        )
        .expect("build the authentication service")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_signing_key_is_created_owner_only_on_first_boot() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create the test directory");
        let key_path = dir.path().join("auth").join("signing.key");
        assert!(!key_path.exists(), "no key exists before the first boot");

        let _authn = boot_authn(dir.path(), MemoryUserStore::new()).await;

        let metadata =
            std::fs::metadata(&key_path).expect("the first boot creates the signing key");
        assert_eq!(metadata.len(), 32, "the key is 32 bytes of OS randomness");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "a signing key must never be readable by group or other"
        );
        let dir_mode = std::fs::metadata(dir.path().join("auth"))
            .expect("the auth directory exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "the directory holding the key is owner-only as well"
        );
    }

    #[tokio::test]
    async fn a_token_minted_before_a_restart_is_accepted_after_it() {
        // The user store is in-memory until T-PM-125, so both "processes" share it: what a restart
        // must preserve for an existing token to keep verifying is the signing key on disk.
        let dir = tempfile::tempdir().expect("create the test directory");
        let key_path = dir.path().join("auth").join("signing.key");
        let store = MemoryUserStore::new();

        let before_restart = boot_authn(dir.path(), store.clone()).await;
        before_restart
            .create_user(
                "admin@example.com".to_string(),
                "correct horse battery staple",
                caddy_rs_authn::Role::admin(),
            )
            .await
            .expect("create the user");
        let tokens = before_restart
            .login("admin@example.com", "correct horse battery staple", None)
            .await
            .expect("mint an access token");
        let persisted_key = std::fs::read(&key_path).expect("read the signing key");
        drop(before_restart);

        // A second daemon instance: new AuthnService, same data directory.
        let after_restart = boot_authn(dir.path(), store).await;
        assert_eq!(
            std::fs::read(&key_path).expect("read the signing key"),
            persisted_key,
            "a restart must reuse the persisted key instead of generating a new one"
        );
        let claims = after_restart
            .verify_access_token(&tokens.access_token)
            .await
            .expect("a token minted before the restart must still be accepted");
        assert_eq!(claims.role, "admin");
    }

    #[tokio::test]
    async fn the_environment_secret_overrides_the_persisted_key() {
        let dir = tempfile::tempdir().expect("create the test directory");
        let key_path = dir.path().join("auth").join("signing.key");

        // A normal first boot persists a key file.
        let _authn = boot_authn(dir.path(), MemoryUserStore::new()).await;
        let on_disk = std::fs::read(&key_path).expect("read the signing key");

        let source = resolve_jwt_secret_source(dir.path(), Some("rotated-by-the-deployment"))
            .expect("resolve the overridden source");
        match &source {
            JwtSecretSource::Master(secret) => assert_eq!(secret, "rotated-by-the-deployment"),
            other => panic!("PM_JWT_SECRET must win over the key file, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&key_path).expect("read the signing key"),
            on_disk,
            "an environment override must not rewrite the persisted key"
        );
    }

    #[test]
    fn an_empty_environment_secret_is_refused_instead_of_falling_back() {
        let dir = tempfile::tempdir().expect("create the test directory");
        let error = resolve_jwt_secret_source(dir.path(), Some(""))
            .expect_err("an empty PM_JWT_SECRET must be refused");
        assert!(
            error.to_string().contains(PM_JWT_SECRET_ENV),
            "the error names the variable: {error}"
        );
        assert!(
            !dir.path().join("auth").exists(),
            "an invalid override must not create a key file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_signing_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create the test directory");
        let auth_dir = dir.path().join("auth");
        std::fs::create_dir_all(&auth_dir).expect("create the auth directory");
        let key_path = auth_dir.join("signing.key");
        std::fs::write(&key_path, [7u8; 32]).expect("write a key file");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640))
            .expect("make the key group-readable");

        let error = resolve_jwt_secret_source(dir.path(), None)
            .expect_err("a key readable by group must be refused");
        let message = error.to_string();
        assert!(
            message.contains(&key_path.display().to_string()),
            "the error names the offending path: {message}"
        );
        assert!(
            message.contains("0o640"),
            "the error names the observed mode: {message}"
        );
    }

    #[tokio::test]
    async fn the_signing_key_never_reaches_the_config_endpoint() {
        let dir = tempfile::tempdir().expect("create the test directory");
        let data_dir = dir.path().join("data");
        let _authn = boot_authn(&data_dir, MemoryUserStore::new()).await;
        let secret =
            std::fs::read(data_dir.join("auth").join("signing.key")).expect("read the signing key");

        let runtime = PmRuntime::open(RuntimeConfig::new(data_dir)).expect("open the runtime");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback listener");
        let addr = listener.local_addr().expect("read the bound address");
        let server = tokio::spawn(async move {
            axum::serve(listener, create_router(ApiState::new(runtime, _authn))).await
        });

        let body = Client::new()
            .get(format!("http://{addr}/api/v1/config"))
            .send()
            .await
            .expect("GET /api/v1/config")
            .text()
            .await
            .expect("read the config payload");
        server.abort();

        assert!(body.contains("\"apps\""), "a config payload: {body}");
        let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        let base64 = base64::engine::general_purpose::STANDARD.encode(secret);
        assert!(
            !body.contains(&hex),
            "the signing key must not appear in /api/v1/config"
        );
        assert!(
            !body.contains(&base64),
            "the base64 form of the signing key must not appear in /api/v1/config"
        );
    }
}
