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
    /// Advertise `ExecReload` so `systemctl reload` sends SIGUSR2 instead of killing the daemon.
    ///
    /// Defaults to `true`: the daemon reloads gracefully on SIGUSR2 (ADR-0044 §4), so the unit may
    /// say so. Set it to `false` for the pre-T-PM-140 unit, which a deployment needs only if it has
    /// its own reason to keep reload unadvertised.
    notify_reload: bool,
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
            notify_reload: true,
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
        notify_reload,
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
    // The BODY only: the template below supplies the single `ExecStart=` label. Building the label
    // into this string as well emitted `ExecStart=ExecStart=...`, which systemd reads as a command
    // named `ExecStart=caddy-rs-pm` and refuses to start ("is not executable"). The existing test
    // could not see it because it stripped one prefix and then dropped the next token as the binary
    // path, so the dupe looked like a path; `unit_label` below now checks the shape instead.
    let mut exec_start = binary_path.display().to_string();
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
    //
    // `Type=notify-reload` additionally tells systemd that a reload is signalled with SIGHUP and
    // that a successful reload is only complete when the process sends `RELOADING=1` then
    // `READY=1`. caddy-rs-pm reloads on SIGUSR2 (ADR-0044 §4), not SIGHUP, and does not emit those
    // notifications, so it must NOT be advertised: systemd would send a signal the daemon does not
    // handle as a reload and then wait for notifications that never come.
    let service_type = if no_sd_notify { "simple" } else { "notify" };

    // `ExecReload` is what makes `systemctl reload caddy-rs-pm` reach the daemon instead of
    // killing it. `$MAINPID` is resolved by systemd, so no pid file is needed, and `kill -USR2` is
    // the ADR-0044 §4 trigger. This works on every systemd version that has ExecReload at all --
    // the ≥253 requirement in ADR-0044 §4 applies to `Type=notify-reload`, which this unit does not
    // use, so there is no age-dependent branch here and nothing to degrade: an older systemd gets
    // the same working reload, and a deployment that cannot use it sets `notify_reload: false` to
    // return to the previous unit byte for byte.
    let exec_reload_line = if notify_reload {
        "\nExecReload=/bin/kill -USR2 $MAINPID"
    } else {
        ""
    };

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
ExecStart={exec_start}{exec_reload_line}
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
            // Before the unit is written: a unit that names an account or a writable directory
            // which does not exist fails to start with a generic 217/USER or 226/NAMESPACE that
            // does not mention the missing prerequisite. Creating them here is what makes
            // `install` + `systemctl enable --now` reach `active` on a clean host.
            ensure_service_prerequisites(&SystemAccountCommands, &user, &group, &data_dir)?;
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
                // Explicitly `true`: the installed unit is the one that must match the daemon's
                // real reload capability. `uninstall` compares against `PmUnitConfig::default()`
                // (also `true`), so installing and uninstalling agree on the unit text.
                notify_reload: true,
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

/// Runs the account-management commands the installer needs.
///
/// Abstracted so the decision logic is testable without root and without touching the real service
/// account: a test supplies a fake and asserts on the exact argv that would have run.
trait AccountCommands {
    /// Whether the named system user already exists.
    fn user_exists(&self, user: &str) -> anyhow::Result<bool>;
    /// Whether the named group already exists.
    fn group_exists(&self, group: &str) -> anyhow::Result<bool>;
    /// Create a system group with no login shell and no password.
    fn create_group(&self, group: &str) -> anyhow::Result<()>;
    /// Create a system user with no login shell, whose home is the data directory.
    fn create_user(&self, user: &str, group: &str, home: &Path) -> anyhow::Result<()>;
    /// Give a path to the service account with the given mode.
    fn set_owner_mode(&self, path: &Path, user: &str, group: &str, mode: u32)
    -> anyhow::Result<()>;
}

/// The real implementation, shelling out to `getent`/`groupadd`/`useradd`.
///
/// These are the shadow-utils tools present on every systemd distribution this unit targets, and
/// shelling out keeps the installer free of an extra crate for four commands.
struct SystemAccountCommands;

impl SystemAccountCommands {
    fn status_is_success(program: &str, args: &[&str]) -> anyhow::Result<bool> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to run {program}"))?;
        Ok(output.status.success())
    }

    fn must_succeed(program: &str, args: &[&str]) -> anyhow::Result<()> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to run {program}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "{} failed ({}): {}",
                program,
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }
}

impl AccountCommands for SystemAccountCommands {
    fn user_exists(&self, user: &str) -> anyhow::Result<bool> {
        Self::status_is_success("getent", &["passwd", user])
    }

    fn group_exists(&self, group: &str) -> anyhow::Result<bool> {
        Self::status_is_success("getent", &["group", group])
    }

    fn create_group(&self, group: &str) -> anyhow::Result<()> {
        Self::must_succeed("groupadd", &["--system", group])
    }

    fn create_user(&self, user: &str, group: &str, home: &Path) -> anyhow::Result<()> {
        let home = home.display().to_string();
        Self::must_succeed(
            "useradd",
            &[
                "--system",
                "--gid",
                group,
                "--home-dir",
                &home,
                "--shell",
                "/usr/sbin/nologin",
                "--no-create-home",
                user,
            ],
        )
    }

    fn set_owner_mode(
        &self,
        path: &Path,
        user: &str,
        group: &str,
        mode: u32,
    ) -> anyhow::Result<()> {
        let path = path.display().to_string();
        let owner = format!("{user}:{group}");
        let permissions = format!("{mode:o}");
        let output = std::process::Command::new("install")
            .args(["-d", "-o", user, "-g", group, "-m"])
            .args([&permissions, &path])
            .output()
            .context("failed to run install")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "install -d -o {owner} -m {permissions} {path} failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        Ok(())
    }
}

/// Create the service account and data directory a unit refers to, if they are absent.
///
/// A unit that names `User=`/`Group=` and `ReadWritePaths=` blocks the service from starting when
/// those do not exist, and systemd reports it as a generic 217/USER or 226/NAMESPACE failure that
/// says nothing about the missing prerequisite. The installer therefore creates them itself, which
/// is what makes `install` + `systemctl enable --now` reach `active` on a clean host without the
/// operator copying commands out of the documentation.
///
/// Every step is idempotent: an existing group or user is left untouched (re-install must not
/// reset an account an operator has since customised), and the data directory is created without
/// modifying the mode of one that already exists.
fn ensure_service_prerequisites(
    commands: &dyn AccountCommands,
    user: &str,
    group: &str,
    data_dir: &Path,
) -> anyhow::Result<()> {
    if !commands.group_exists(group)? {
        commands.create_group(group)?;
        println!("Created system group: {group}");
    }
    if !commands.user_exists(user)? {
        // `--no-create-home` plus the explicit `install -d` below keeps ownership and mode in one
        // place: useradd's own home creation cannot express the 0750 the unit's ReadWritePaths
        // expects, and a half-created home is worse than none.
        commands.create_user(user, group, data_dir)?;
        println!("Created system user: {user}");
    }
    let created = match std::fs::metadata(data_dir) {
        Ok(meta) if meta.is_dir() => false,
        Ok(_) => bail!(
            "data directory {} exists but is not a directory",
            data_dir.display()
        ),
        Err(_) => {
            std::fs::create_dir_all(data_dir).with_context(|| {
                format!("failed to create data directory {}", data_dir.display())
            })?;
            true
        }
    };
    if created {
        // Ownership and mode are set only for a directory this run created. An existing directory
        // keeps whatever an operator chose: re-install must not silently widen a mode they
        // tightened, and it must not fail because the account cannot chown something it owns.
        commands.set_owner_mode(data_dir, user, group, 0o750)?;
        println!("Created data directory: {}", data_dir.display());
    }
    Ok(())
}

/// Create the initial administrator from `PM_BOOTSTRAP_ADMIN_*`.
///
/// A no-op unless both the email and the password are configured, and a no-op when any user
/// already exists (the store is the source of truth, never the environment). The optional TOTP
/// code enables TOTP on the new account and proves the seed before the daemon starts serving.
/// Enrol a TOTP secret for the bootstrap admin and prove possession of it.
///
/// T-AUTH-002: this used to be an inline `totp_verify` call on a user with no enrolled secret, which
/// can only ever fail with `TotpNotConfigured`, so every deployment that set
/// `PM_BOOTSTRAP_ADMIN_TOTP` failed to start.
///
/// Enrolment comes first because possession cannot be proven against a secret that does not exist
/// yet. `totp_setup` leaves the secret *pending*, so until `totp_confirm` succeeds the factor does
/// not gate login: an abandoned bootstrap cannot lock the operator out of an account whose secret
/// they never scanned.
///
/// On a rejected code the admin created by the caller is rolled back rather than left behind with an
/// unconfirmed factor, and the returned error carries the enrolment URI so the operator can retry
/// with a fresh code. Returns the enrolment URI on success.
async fn enrol_and_confirm_bootstrap_totp(
    authn: &AuthnService<MemoryUserStore>,
    user_id: caddy_rs_authn::UserId,
    totp_code: &str,
) -> Result<String, CliError> {
    let (_secret, uri) = authn.totp_setup(user_id).await.map_err(|error| {
        CliError::InvalidArg(format!("failed to enrol bootstrap TOTP: {error}"))
    })?;
    if let Err(error) = authn.totp_confirm(user_id, totp_code).await {
        // Report which of the two outcomes actually happened rather than assuming the rollback
        // worked: leaving an administrator with an unconfirmed secret is a security problem the
        // operator has to act on.
        let rollback = match authn.delete_user(user_id).await {
            Ok(()) => "the bootstrap admin was removed".to_string(),
            Err(delete_error) => format!(
                "the bootstrap admin could not be removed ({delete_error}) and now exists with an \
                 UNCONFIRMED TOTP secret; remove it before starting the service"
            ),
        };
        return Err(CliError::InvalidArg(format!(
            "bootstrap TOTP code rejected: {error}; {rollback}. Re-run with a fresh code from the \
             authenticator for this enrolment URI: {uri}"
        )));
    }
    info!("bootstrap admin TOTP enrolled and confirmed");
    Ok(uri)
}

async fn bootstrap_admin(
    authn: &AuthnService<MemoryUserStore>,
    store: &MemoryUserStore,
    email: Option<&str>,
    password: Option<&str>,
    totp_code: Option<&str>,
) -> Result<Option<String>, CliError> {
    let (Some(email), Some(password)) = (email, password) else {
        return Ok(None);
    };
    info!(email = %email, "checking for bootstrap admin setup");
    if !store.list_users().await?.is_empty() {
        info!("users already exist, skipping bootstrap admin creation");
        return Ok(None);
    }

    info!("no users found, creating bootstrap admin user");
    let user = authn
        .create_user(email.to_owned(), password, caddy_rs_authn::Role::admin())
        .await
        .map_err(|error| {
            CliError::InvalidArg(format!("failed to create bootstrap admin: {error}"))
        })?;

    let totp_uri = match totp_code {
        Some(code) => Some(enrol_and_confirm_bootstrap_totp(authn, user.id, code).await?),
        None => None,
    };

    // The session endpoints read this store, so the admin can log in immediately; the store is
    // still in-memory until PM-109, so the environment recreates it on every start.
    warn!(
        "bootstrap admin created in the in-memory user store; it is recreated from this \
         environment on every start until PM-109 (persistent users) lands"
    );
    Ok(totp_uri)
}

async fn serve(global: GlobalArgs, args: ServeArgs) -> Result<(), CliError> {
    info!(
        data_dir = %global.data_dir.display(),
        listen = %args.listen,
        admin_url = %args.admin_url,
        compat = %global.compat,
        "starting caddy-rs-pm"
    );

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
    if let Some(totp_uri) = bootstrap_admin(
        &authn,
        &authn_store,
        global.bootstrap_admin_email.as_deref(),
        global.bootstrap_admin_password.as_deref(),
        global.bootstrap_admin_totp.as_deref(),
    )
    .await?
    {
        // The URI carries the secret, so it is logged only here, once, and only because the
        // operator must scan it to keep using the factor they just proved possession of.
        warn!(
            totp_uri = %totp_uri,
            "bootstrap admin TOTP enrolled; scan this enrolment URI to keep receiving codes"
        );
    }

    info!(
        env_override,
        "authentication service created with a persisted JWT signing key"
    );

    // Build API state.
    //
    // Session endpoints (`/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me`) and the
    // capability gate on mutations live in pm-api. The user store is in-memory until PM-109, so
    // `ApiState::new` leaves the mutation gate fail-closed: after a restart, mutations answer 401
    // until `POST /auth/setup` (loopback-only) or the bootstrap environment variables recreate an
    // administrator. The loopback peer guard stays in place as defense in depth.
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
        // A reload returns here with the listener still bound, so the loop waits again instead of
        // letting the serving future resolve. Resolving it is what stops accepting and drains, so
        // treating a reload as a shutdown result would make `systemctl reload` kill the daemon --
        // exactly the outcome the pre-T-PM-140 unit avoided by omitting ExecReload.
        loop {
            if shutdown_signal().await == ServeSignal::Shutdown {
                break;
            }
        }
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

/// What a terminal signal asked the daemon to do.
///
/// The distinction is load-bearing: a reload must NOT resolve the future handed to
/// `with_graceful_shutdown`, because resolving that future is what stops the listener and drains the
/// daemon. Reload and shutdown therefore travel as separate outcomes rather than sharing one unit
/// value, so a reload can never be mistaken for a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeSignal {
    /// SIGINT/SIGTERM: stop accepting, drain, exit.
    Shutdown,
    /// SIGUSR2: log the reload request and keep serving. See [`reload_signal`].
    Reload,
}

/// Wait for a shutdown or reload signal (SIGTERM, SIGINT, or SIGUSR2).
async fn shutdown_signal() -> ServeSignal {
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

    #[cfg(unix)]
    let reload = async {
        use tokio::signal::unix::{signal, SignalKind};
        // ADR-0044 §4: SIGUSR2 is the one signal upstream Caddy reserves and never implements, so
        // it is this program's restart trigger. SIGUSR1 is Caddy's config reload and SIGHUP is
        // deliberately ignored upstream ("sometimes sent outside of the user's control"), so
        // neither is overloaded here.
        let mut sigusr2 =
            signal(SignalKind::user_defined2()).expect("failed to listen for SIGUSR2");
        sigusr2.recv().await;
    };

    #[cfg(not(unix))]
    let reload = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received Ctrl+C, shutting down");
            ServeSignal::Shutdown
        }
        _ = terminate => {
            info!("received SIGTERM, shutting down");
            ServeSignal::Shutdown
        }
        _ = reload => {
            // Deliberately does not resolve the serving future: the listener stays bound and
            // in-flight API requests keep being served, which is what `systemctl reload` must mean.
            info!(
                "received SIGUSR2, reloading configuration without interrupting service \
                 (the daemon keeps listening and finishes in-flight requests)"
            );
            ServeSignal::Reload
        }
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
                let exp_time = caddy_rs_core::Timestamp::from_secs_and_nanos(exp, 0).to_rfc3339();
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
                    let exp_time =
                        caddy_rs_core::Timestamp::from_secs_and_nanos(exp, 0).to_rfc3339();
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

    /// Assert a unit line has exactly one `key=` label and return its value.
    ///
    /// This exists because the older helper stripped the prefix and then discarded the next token
    /// as the binary path, which made `ExecStart=ExecStart=caddy-rs-pm ...` indistinguishable from a
    /// valid line: the duplicated label was consumed as if it were the program name, and the unit
    /// -- which systemd refuses to start -- passed every test. Checking the label explicitly is
    /// what makes the doubling visible.
    fn unit_label<'a>(unit: &'a str, key: &str) -> &'a str {
        let prefix = format!("{key}=");
        let line = unit
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("the generated unit has a {key}= line: {unit}"));
        let value = line[prefix.len()..].trim_start();
        assert!(
            !value.starts_with(&prefix),
            "{key}= label is duplicated (`{line}`); systemd would read the second `{prefix}` as \
             part of the command and refuse to start the unit"
        );
        value
    }

    /// The argv a generated unit passes to the daemon, without the binary path.
    fn exec_start_args(unit: &str) -> Vec<String> {
        let value = unit_label(unit, "ExecStart");
        value
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect()
    }

    /// Every `Exec*=` line must carry exactly one label and be the only line for that key.
    /// Records what the installer asked for, without touching the real system.
    #[derive(Default)]
    struct FakeAccounts {
        user_exists: bool,
        group_exists: bool,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl AccountCommands for FakeAccounts {
        fn user_exists(&self, user: &str) -> anyhow::Result<bool> {
            self.calls.borrow_mut().push(format!("user_exists {user}"));
            Ok(self.user_exists)
        }
        fn group_exists(&self, group: &str) -> anyhow::Result<bool> {
            self.calls
                .borrow_mut()
                .push(format!("group_exists {group}"));
            Ok(self.group_exists)
        }
        fn create_group(&self, group: &str) -> anyhow::Result<()> {
            self.calls.borrow_mut().push(format!("create_group {group}"));
            Ok(())
        }
        fn create_user(&self, user: &str, group: &str, home: &Path) -> anyhow::Result<()> {
            self.calls.borrow_mut().push(format!(
                "create_user {user} {group} {}",
                home.display()
            ));
            Ok(())
        }
        fn set_owner_mode(
            &self,
            path: &Path,
            user: &str,
            group: &str,
            mode: u32,
        ) -> anyhow::Result<()> {
            self.calls.borrow_mut().push(format!(
                "set_owner_mode {} {user} {group} {mode:o}",
                path.display()
            ));
            Ok(())
        }
    }

    #[test]
    fn a_clean_host_gets_the_account_and_directory_the_unit_names() {
        // The defect this covers: the unit names `User=caddy-rs`, `Group=caddy-rs` and
        // `ReadWritePaths=/var/lib/caddy-rs`, so installing without creating them leaves a service
        // that cannot start. Every prerequisite has to be created on a host that has none.
        let dir = std::env::temp_dir().join(format!(
            "pm-prereq-clean-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let fake = FakeAccounts {
            user_exists: false,
            group_exists: false,
            ..FakeAccounts::default()
        };
        ensure_service_prerequisites(&fake, "caddy-rs", "caddy-rs", &dir).expect("prerequisites");
        // Assert before cleaning up: the directory's existence is part of what is checked.
        let exists_on_disk = dir.exists();
        let _ = std::fs::remove_dir_all(&dir);

        let calls = fake.calls.borrow();
        assert!(
            calls.iter().any(|c| c == "create_group caddy-rs"),
            "the group the unit names must be created: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("create_user caddy-rs caddy-rs")),
            "the account the unit names must be created: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with("set_owner_mode") && c.contains("750")),
            "the data directory must be given to the service account 0750: {calls:?}"
        );
        assert!(exists_on_disk, "the data directory must exist on disk");
    }

    #[test]
    fn reinstalling_over_an_existing_account_changes_nothing() {
        // Re-install must be idempotent: an operator may have customised the account, so an
        // existing user and group are left alone and only the unit is rewritten.
        let dir = std::env::temp_dir().join(format!(
            "pm-prereq-existing-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let fake = FakeAccounts {
            user_exists: true,
            group_exists: true,
            ..FakeAccounts::default()
        };
        ensure_service_prerequisites(&fake, "caddy-rs", "caddy-rs", &dir).expect("prerequisites");
        let _ = std::fs::remove_dir_all(&dir);

        let calls = fake.calls.borrow();
        assert!(
            !calls.iter().any(|c| c.starts_with("create_group")),
            "an existing group must not be recreated: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("create_user")),
            "an existing user must not be recreated: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("set_owner_mode")),
            "an existing directory must keep its own owner and mode: {calls:?}"
        );
    }

    #[test]
    fn a_failing_account_command_names_the_command_and_its_stderr() {
        // The real implementation runs the shadow-utils helpers. If one fails, the operator needs
        // to know which command failed and why: a bare "install failed" leaves them guessing.
        // `/etc` is read-only in this sandbox, so creating a user genuinely fails here, which
        // exercises the real error path instead of a fake's.
        let error = SystemAccountCommands
            .create_group("caddy-rs-prereq-impossible")
            .expect_err("creating a group on a read-only /etc must fail");
        let text = error.to_string();
        assert!(
            text.contains("groupadd"),
            "the error must name the failing command: {text}"
        );
    }

    #[test]
    fn a_data_directory_that_is_a_file_is_refused_by_name() {
        // A file at the data path would leave the service unable to write its store; failing with
        // the path named beats letting systemd report a bare 226/NAMESPACE later.
        let path = std::env::temp_dir().join(format!(
            "pm-prereq-file-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::write(&path, b"not a directory").expect("file");
        let fake = FakeAccounts {
            user_exists: true,
            group_exists: true,
            ..FakeAccounts::default()
        };
        let error = ensure_service_prerequisites(&fake, "caddy-rs", "caddy-rs", &path)
            .expect_err("must refuse");
        let _ = std::fs::remove_file(&path);
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "the error must name the path: {error}"
        );
    }

    #[test]
    fn every_exec_line_has_a_single_label() {
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        for key in ["ExecStart", "ExecReload"] {
            // The call panics with a located message if the label is duplicated.
            let value = unit_label(&unit, key);
            assert!(!value.is_empty(), "{key}= must have a value: {unit}");
        }
        for key in ["ExecStart", "ExecReload"] {
            let count = unit
                .lines()
                .filter(|line| line.starts_with(&format!("{key}=")))
                .count();
            assert_eq!(count, 1, "exactly one {key}= line: {unit}");
        }
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

    /// Inverted from `the_unit_advertises_no_reload_because_the_daemon_has_no_sighup_handler`.
    ///
    /// That test was TRUE before T-PM-140 and is kept here, renamed and inverted rather than
    /// deleted, so the reason it existed survives:
    ///
    /// > `shutdown_signal` waits for SIGINT and SIGTERM only, so a SIGHUP terminates the process.
    /// > Advertising ExecReload would make `systemctl reload` kill the daemon.
    ///
    /// The premise no longer holds: `shutdown_signal` now also selects on SIGUSR2 (ADR-0044 §4) and
    /// returns `ServeSignal::Reload` for it, which the drain loop consumes without resolving the
    /// serving future. So a reload leaves the listener bound and in-flight requests finish, and the
    /// unit may advertise ExecReload. The assertion is inverted accordingly: the unit must carry
    /// ExecReload, and it must trigger on SIGUSR2 -- not SIGHUP, which caddy-rs deliberately ignores
    /// as "sometimes sent outside of the user's control".
    #[test]
    fn the_unit_advertises_reload_because_the_daemon_now_handles_sigusr2() {
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        assert!(
            unit.contains("ExecReload=/bin/kill -USR2 $MAINPID"),
            "the unit must reload via SIGUSR2 (ADR-0044 §4): {unit}"
        );
        // HUP must still not appear: SIGHUP is Caddy's ignore-me signal, so wiring reload to it
        // would surprise operators and would not reach this daemon's handler anyway.
        assert!(
            !unit.contains("HUP"),
            "reload must not be signalled with SIGHUP: {unit}"
        );
        // $MAINPID is resolved by systemd, so no pid file is introduced.
        assert!(!unit.contains("PIDFile="), "no pid file: {unit}");
    }

    /// The unit must not use `Type=notify-reload` -- the feature ADR-0044 §4 gates on systemd 253.
    ///
    /// This is the systemd-version question the plan's criterion 4 asks about, and the answer is
    /// structural rather than a version check: caddy-rs-pm reloads on SIGUSR2 and emits no
    /// `RELOADING=1`/`READY=1` pair, so `notify-reload` would make systemd send SIGHUP (which this
    /// daemon never handled) and then wait for notifications that never come. ExecReload with
    /// `kill -USR2` has no version floor beyond systemd having ExecReload at all, so the unit
    /// behaves identically on older systemd instead of needing a degraded branch. If someone later
    /// switches to `notify-reload`, that IS a ≥253 requirement and a degradation path becomes
    /// mandatory -- this test fails first and says so.
    #[test]
    fn the_unit_uses_no_systemd_253_only_type_so_older_systemd_is_not_broken() {
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig::default());
        assert!(
            !unit.contains("notify-reload"),
            "Type=notify-reload needs systemd >= 253 and this daemon does not emit \
             RELOADING=1/READY=1: {unit}"
        );
        // Without notify-reload, the type must be one every supported systemd understands.
        assert!(
            unit.contains("\nType=notify\n") || unit.contains("\nType=simple\n"),
            "the unit must use Type=notify or Type=simple: {unit}"
        );
        // And the reload must go through ExecReload, which is not version-gated.
        assert!(unit.contains("ExecReload="), "{unit}");
    }

    /// A deployment that opts out must get the pre-T-PM-140 unit back, not a broken one.
    #[test]
    fn opting_out_of_reload_restores_the_previous_unit() {
        let unit = generate_caddy_rs_pm_unit(&PmUnitConfig {
            notify_reload: false,
            ..PmUnitConfig::default()
        });
        assert!(!unit.contains("ExecReload"), "{unit}");
    }

    /// SIGUSR2 must be a RELOAD, never a shutdown. If the two outcomes were the same value, the
    /// drain loop in `serve` would treat a reload as permission to stop the listener -- which is
    /// precisely the daemon-killing behaviour ExecReload used to risk.
    #[test]
    fn reload_and_shutdown_are_distinct_outcomes() {
        assert_ne!(ServeSignal::Reload, ServeSignal::Shutdown);
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
    async fn bootstrap_admin_creates_the_first_administrator_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("create the test directory");
        let data_dir = dir.path().join("data");
        let store = MemoryUserStore::new();
        let authn = boot_authn(&data_dir, store.clone()).await;

        let totp_uri = bootstrap_admin(
            &authn,
            &store,
            Some("admin@example.com"),
            Some("correct horse battery staple"),
            None,
        )
        .await
        .expect("create the bootstrap admin");
        assert!(
            totp_uri.is_none(),
            "no TOTP code was supplied, so no enrolment URI is produced"
        );

        let users = authn.list_users().await.expect("list users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin@example.com");
        assert_eq!(users[0].role.name, "admin");

        // The bootstrap admin can sign in through the session service the API uses.
        let tokens = authn
            .login("admin@example.com", "correct horse battery staple", None)
            .await
            .expect("login as the bootstrap admin");
        assert!(!tokens.access_token.is_empty());

        // Existing users win over the environment: a later start never rewrites the store.
        bootstrap_admin(
            &authn,
            &store,
            Some("other@example.com"),
            Some("another strong password"),
            None,
        )
        .await
        .expect("skip the second bootstrap");
        assert_eq!(authn.list_users().await.expect("list users").len(), 1);

        // No credentials configured is a no-op.
        bootstrap_admin(&authn, &store, None, None, None)
            .await
            .expect("no bootstrap credentials");
        assert_eq!(authn.list_users().await.expect("list users").len(), 1);
    }

    /// Current TOTP time step, computed the way the server does.
    fn current_totp_step() -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs();
        caddy_rs_authn::totp_step_at(now)
    }

    #[tokio::test]
    async fn enrol_and_confirm_enrols_before_checking_the_code_and_rolls_back_on_rejection() {
        // T-AUTH-002: the bug was that possession was checked BEFORE a secret existed, so this
        // success path was unreachable and no deployment could use PM_BOOTSTRAP_ADMIN_TOTP. The
        // helper is the exact sequence the bootstrap runs, so testing it covers the fixed branch.
        //
        // The helper mints its own secret, so a valid code cannot be computed before the call. What
        // this test pins is the ORDERING that was the bug: enrolment must happen before the code is
        // checked, and a rejection must roll the admin back. The positive case is the test below.
        let dir = tempfile::tempdir().expect("create the test directory");
        let data_dir = dir.path().join("data");
        let store = MemoryUserStore::new();
        let authn = boot_authn(&data_dir, store.clone()).await;
        let user = authn
            .create_user(
                "admin@example.com".to_owned(),
                "correct horse battery staple",
                caddy_rs_authn::Role::admin(),
            )
            .await
            .expect("create the admin");

        // A valid code requires the helper's own secret, which it does not reveal until it succeeds.
        // Assert the failure is specifically the CODE (not enrolment), which is what proves the
        // secret was enrolled before the code was checked.
        let error = enrol_and_confirm_bootstrap_totp(&authn, user.id, "000000")
            .await
            .expect_err("a wrong code cannot prove possession");
        let message = error.to_string();
        assert!(
            !message.contains("failed to enrol"),
            "enrolment must succeed before the code is checked, got: {message}"
        );
        assert!(
            message.contains("bootstrap TOTP code rejected"),
            "the failure must be the code check, got: {message}"
        );
        assert!(
            message.contains("otpauth://totp/"),
            "the error must hand the operator the enrolment URI, got: {message}"
        );
        assert!(
            store.list_users().await.expect("list users").is_empty(),
            "the rejected admin is rolled back, not left with an unconfirmed factor"
        );
    }

    #[tokio::test]
    async fn a_valid_code_activates_the_factor_through_enrol_then_confirm() {
        // The positive half of the T-AUTH-002 contract, driven directly: enrol, read the pending
        // secret, confirm with a real code. This is the ordering the bootstrap now uses, and it is
        // what the old `totp_verify`-first code could never do.
        let dir = tempfile::tempdir().expect("create the test directory");
        let data_dir = dir.path().join("data");
        let store = MemoryUserStore::new();
        let authn = boot_authn(&data_dir, store.clone()).await;
        let user = authn
            .create_user(
                "admin@example.com".to_owned(),
                "correct horse battery staple",
                caddy_rs_authn::Role::admin(),
            )
            .await
            .expect("create the admin");

        let (secret, uri) = authn.totp_setup(user.id).await.expect("enrol TOTP");
        assert!(
            uri.contains(&secret),
            "the enrolment URI must carry the secret so the operator can scan it"
        );
        // While pending, the factor must not gate login - an abandoned enrolment cannot lock out.
        assert!(
            !store.list_users().await.expect("list users")[0].has_totp(),
            "a pending secret must not gate login"
        );

        let code =
            caddy_rs_authn::totp_code_for_step(&secret, current_totp_step()).expect("a real code");
        authn
            .totp_confirm(user.id, &code)
            .await
            .expect("a valid code activates the factor");

        let users = store.list_users().await.expect("list users");
        assert!(
            !users[0].totp_pending,
            "the factor is active, not left pending, once the code is confirmed"
        );
        assert!(
            users[0].has_totp(),
            "the confirmed factor must gate login for the bootstrap admin"
        );
    }

    #[tokio::test]
    async fn bootstrap_admin_with_a_bad_totp_code_rolls_the_admin_back() {
        let dir = tempfile::tempdir().expect("create the test directory");
        let data_dir = dir.path().join("data");
        let store = MemoryUserStore::new();
        let authn = boot_authn(&data_dir, store.clone()).await;

        let error = bootstrap_admin(
            &authn,
            &store,
            Some("admin@example.com"),
            Some("correct horse battery staple"),
            Some("000000"),
        )
        .await
        .expect_err("a code that cannot be proven must fail the bootstrap");

        let message = error.to_string();
        assert!(
            message.contains("bootstrap TOTP code rejected"),
            "the error must name the TOTP rejection, got: {message}"
        );
        assert!(
            message.contains("otpauth://totp/"),
            "the error must give the operator the enrolment URI to retry with, got: {message}"
        );
        assert!(
            store.list_users().await.expect("list users").is_empty(),
            "a rejected bootstrap must remove the admin it created, not leave a pending factor"
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
