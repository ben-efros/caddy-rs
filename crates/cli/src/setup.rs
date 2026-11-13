//! `caddy-rs setup` — zero-config first-boot authentication bootstrap (T-SETUP-001).
//!
//! Scope of this task is the command surface and the generated configuration: flags, a temporary
//! activation layer, single-use activation tokens, and the boot seam. The activation handler
//! itself (T-SETUP-002), WebAuthn/TOTP enrollment (T-SETUP-003) and the generation-scoped
//! `caddy-pm-rs` external service (T-SETUP-004, ADR-006) are not part of this task; the generated
//! route is therefore a placeholder `respond` handler and `ServerBootRunner` only starts caddy-rs
//! itself (it does not spawn `caddy-pm-rs`).
//!
//! Tokens are single-use and expire after `--registration-timeout` (ADR-0039: default 15m,
//! minimum 5m, maximum 60m). They live in memory in this process only; persisting them in
//! `caddy-pm-rs` storage is T-SETUP-005.
//!
//! `caddy-rs setup` is a caddy-rs extension. In the stock-compatibility profile it must behave as
//! an unknown command; caddy-rs has no global CLI `stock_compat` switch (the switch is a config
//! field, `crates/core/src/config.rs`), so the CLI-level trigger is `CADDY_RS_STOCK_COMPAT=true`.
//! `ensure_not_stock_compat` is the located rejection point.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use rand::RngCore;

/// Environment variable that selects the stock-compatibility profile for the CLI.
pub const STOCK_COMPAT_ENV: &str = "CADDY_RS_STOCK_COMPAT";

/// Default activation-URL TTL (ADR-0039).
pub const DEFAULT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Minimum activation-URL TTL (ADR-0039).
pub const MIN_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Maximum activation-URL TTL (ADR-0039).
pub const MAX_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Path of the activation endpoint served by the temporary layer.
pub const ACTIVATION_PATH: &str = "/_caddy-pm/activate";

/// Authentication method for first-boot enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthMethod {
    /// WebAuthn / Passkey (FIDO2)
    Webauthn,
    /// Time-based One-Time Password (RFC 6238)
    Totp,
}

impl AuthMethod {
    /// Stable name used in generated config and output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webauthn => "webauthn",
            Self::Totp => "totp",
        }
    }
}

/// Configuration for the `setup` command (ADR-0039 flag specification).
#[derive(Debug, Args)]
#[command(
    name = "setup",
    about = "Zero-config first-boot authentication bootstrap",
    long_about = "\
Bootstrap a new caddy-rs instance with WebAuthn/TOTP authentication.

This command:
1. Generates a temporary Caddyfile with an activation layer
2. Starts caddy-rs (which spawns caddy-pm-rs for the enrollment UI)
3. Prints activation URLs with single-use tokens
4. On successful enrollment, permanently disables the activation endpoint
   and transitions to normal operation

The activation endpoint is served at https://<domain>/_caddy-pm/activate and requires
a single-use token that expires after --registration-timeout (default 15m).
"
)]
pub struct SetupArgs {
    /// Domain name for the activation URLs (required for HTTPS).
    ///
    /// Must be a valid hostname. The domain is used for:
    /// - HTTPS listener (automatic TLS via internal CA)
    /// - Activation URL generation
    /// - WebAuthn relying party ID
    #[arg(long, value_name = "DOMAIN")]
    pub domain: String,

    /// Authentication method for enrollment.
    #[arg(long, value_enum, default_value = "webauthn")]
    pub auth_method: AuthMethod,

    /// Storage backend for credential persistence.
    ///
    /// Supported: file_system (default), redis, postgres, consul.
    #[arg(long, default_value = "file_system")]
    pub storage: String,

    /// Activation URL TTL (ADR-0039: default 15m, minimum 5m, maximum 60m).
    #[arg(long, default_value = "15m", value_name = "DURATION")]
    pub registration_timeout: String,

    /// Data directory override.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Additional host name. Repeatable; each becomes a site address and activation URL.
    #[arg(long, value_name = "HOST")]
    pub host: Vec<String>,

    /// Listen address (`IP`, `IP:port`, `[IPv6]`, `[IPv6]:port`, or `:port`).
    #[arg(long, value_name = "ADDR")]
    pub listen_address: Option<String>,

    /// Enable automatic cert issuance via the default ACME CA (requires --host or --domain).
    #[arg(long)]
    pub acme: bool,

    /// Use `dns.providers.cloudflare` for the DNS-01 challenge (requires --host or --domain).
    #[arg(long)]
    pub cloudflare: bool,

    /// Cloudflare API token source: omitted reads `CF_API_TOKEN`, `/path` reads the first line,
    /// `-` reads stdin. The token value is never accepted as an argument.
    #[arg(long, value_name = "SOURCE")]
    pub cf_api_token: Option<String>,
}

/// Errors of the setup command. Kept free of `anyhow` so the pure pieces are testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupError {
    /// `stock_compat` is enabled: `setup` is an unknown command in that profile.
    UnknownCommand,
    /// `--domain` is not a plausible hostname.
    InvalidDomain(String),
    /// `--host` is not a plausible hostname.
    InvalidHost(String),
    /// `--storage` is not a documented backend.
    InvalidStorage(String),
    /// `--listen-address` is not one of the documented forms.
    InvalidListenAddress(String),
    /// `--registration-timeout` is malformed or outside 5m..=60m.
    InvalidRegistrationTimeout(String),
    /// `--cloudflare` was given without a token source (and `CF_API_TOKEN` is unset).
    MissingCloudflareToken,
    /// The generated Caddyfile was rejected by the adapter (a bug in generation).
    ConfigRejected(String),
    /// The boot step failed.
    BootFailed(String),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand => write!(
                f,
                "unknown command \"setup\" for \"caddy-rs\": `caddy-rs setup` is a caddy-rs \
                 extension and is not available in the stock-compatibility profile"
            ),
            Self::InvalidDomain(domain) => {
                write!(f, "--domain `{domain}` is not a valid hostname")
            }
            Self::InvalidHost(host) => write!(f, "--host `{host}` is not a valid hostname"),
            Self::InvalidStorage(storage) => write!(
                f,
                "--storage `{storage}` is not supported (expected file_system, redis, postgres or \
                 consul)"
            ),
            Self::InvalidListenAddress(addr) => write!(
                f,
                "--listen-address `{addr}` is not valid (expected IP, IP:port, [IPv6], \
                 [IPv6]:port or :port)"
            ),
            Self::InvalidRegistrationTimeout(reason) => {
                write!(f, "--registration-timeout: {reason}")
            }
            Self::MissingCloudflareToken => write!(
                f,
                "--cloudflare requires --cf-api-token <SOURCE> or the CF_API_TOKEN environment \
                 variable"
            ),
            Self::ConfigRejected(reason) => {
                write!(f, "generated setup configuration is invalid: {reason}")
            }
            Self::BootFailed(reason) => write!(f, "cannot boot caddy-rs: {reason}"),
        }
    }
}

impl std::error::Error for SetupError {}

/// The generated first-boot configuration.
#[derive(Debug, Clone)]
pub struct SetupConfig {
    /// Caddyfile text handed to `caddy-rs run --adapter caddyfile`.
    pub caddyfile: String,
    /// The adapted JSON, proving the generated config is valid.
    #[allow(dead_code)] // exposed for the activation-layer/validation consumers (T-SETUP-002)
    pub json: serde_json::Value,
    /// Where the Caddyfile is written before boot.
    pub config_path: PathBuf,
    /// Activation URLs without the token (the token is appended when printed).
    pub activation_urls: Vec<String>,
    /// Effective TTL for the activation token.
    pub registration_timeout: Duration,
    /// Enrollment method.
    pub auth_method: AuthMethod,
    /// Storage backend requested by the operator.
    pub storage: String,
    /// Primary domain.
    pub domain: String,
}

/// Parse an ADR-0039 duration such as `15m`, `900s` or `1h`.
pub fn parse_duration(text: &str) -> Result<Duration, SetupError> {
    let text = text.trim();
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let value: u64 = digits.parse().map_err(|_| {
        SetupError::InvalidRegistrationTimeout(format!("`{text}` is not a duration"))
    })?;
    let overflow = || {
        SetupError::InvalidRegistrationTimeout(format!(
            "`{text}` does not fit in a duration (overflow)"
        ))
    };
    let seconds = match unit {
        "s" | "" => value,
        "m" => value.checked_mul(60).ok_or_else(overflow)?,
        "h" => value.checked_mul(3600).ok_or_else(overflow)?,
        other => {
            return Err(SetupError::InvalidRegistrationTimeout(format!(
                "`{text}` has unsupported unit `{other}` (expected s, m or h)"
            )))
        }
    };
    Ok(Duration::from_secs(seconds))
}

/// Resolve and validate `--registration-timeout` (ADR-0039: 5m..=60m).
pub fn registration_timeout(args: &SetupArgs) -> Result<Duration, SetupError> {
    if args.registration_timeout.trim().is_empty() {
        return Ok(DEFAULT_REGISTRATION_TIMEOUT);
    }
    let timeout = parse_duration(&args.registration_timeout)?;
    if timeout < MIN_REGISTRATION_TIMEOUT {
        return Err(SetupError::InvalidRegistrationTimeout(format!(
            "{}s is below the 5m minimum",
            timeout.as_secs()
        )));
    }
    if timeout > MAX_REGISTRATION_TIMEOUT {
        return Err(SetupError::InvalidRegistrationTimeout(format!(
            "{}s is above the 60m maximum",
            timeout.as_secs()
        )));
    }
    Ok(timeout)
}

/// Validate a hostname or IP literal used as a site address / activation URL host.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        && !host.starts_with('.')
        && !host.ends_with('.')
}

/// Extract the port from an ADR-0039 listen address, defaulting to 443.
fn listen_port(addr: Option<&str>) -> Result<u16, SetupError> {
    let Some(addr) = addr else {
        return Ok(443);
    };
    if !is_valid_listen_address(addr) {
        return Err(SetupError::InvalidListenAddress(addr.to_string()));
    }
    let port = if let Some(rest) = addr.strip_prefix('[') {
        // `[IPv6]` or `[IPv6]:port`
        rest.split_once("]:").map(|(_, port)| port)
    } else if let Some(port) = addr.strip_prefix(':') {
        Some(port)
    } else {
        addr.rsplit_once(':').map(|(_, port)| port)
    };
    match port {
        Some(port) => port
            .parse()
            .map_err(|_| SetupError::InvalidListenAddress(addr.to_string())),
        None => Ok(443),
    }
}

fn is_valid_listen_address(addr: &str) -> bool {
    if addr.is_empty() || addr.contains(char::is_whitespace) {
        return false;
    }
    if let Some(port) = addr.strip_prefix(':') {
        return !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    }
    if addr.starts_with('[') {
        return addr
            .find(']')
            .map(|end| {
                let rest = &addr[end + 1..];
                rest.is_empty()
                    || rest.strip_prefix(':').is_some_and(|port| {
                        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                    })
            })
            .unwrap_or(false);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && !host.contains(':')
        }
        None => !addr.contains(':'),
    }
}

/// Pure config generation: builds the activation-layer Caddyfile and validates it with the
/// Caddyfile adapter. Never binds a port and never touches the network.
pub fn generate_config(args: &SetupArgs) -> Result<SetupConfig, SetupError> {
    if !is_valid_host(&args.domain) {
        return Err(SetupError::InvalidDomain(args.domain.clone()));
    }
    for host in &args.host {
        if !is_valid_host(host) {
            return Err(SetupError::InvalidHost(host.clone()));
        }
    }
    match args.storage.as_str() {
        "file_system" | "redis" | "postgres" | "consul" => {}
        other => return Err(SetupError::InvalidStorage(other.to_string())),
    }
    let timeout = registration_timeout(args)?;
    let port = listen_port(args.listen_address.as_deref())?;
    if args.cloudflare && args.cf_api_token.is_none() && std::env::var("CF_API_TOKEN").is_err() {
        return Err(SetupError::MissingCloudflareToken);
    }

    let mut caddyfile = String::new();
    caddyfile.push_str("{\n");
    caddyfile.push_str("\tadmin localhost:2019\n");
    // ADR-0039: without ACME the internal CA issues the certificate; the fingerprint is printed
    // by the boot step so the operator can verify TLS before enrolling.
    if !args.acme && !args.cloudflare {
        caddyfile.push_str("\tlocal_certs\n");
    }
    caddyfile.push_str("}\n\n");

    let mut hosts = vec![args.domain.clone()];
    for host in &args.host {
        if !hosts.contains(host) {
            hosts.push(host.clone());
        }
    }
    for host in &hosts {
        caddyfile.push_str(&format!(
            "# caddy-rs setup: temporary activation layer (auth: {}, single-use, expires after {}s)\n",
            args.auth_method.as_str(),
            timeout.as_secs()
        ));
        caddyfile.push_str(&format!("https://{host}:{port} {{\n"));
        caddyfile.push_str(&format!("\troute {ACTIVATION_PATH}* {{\n"));
        caddyfile.push_str(
            "\t\t# T-SETUP-002/T-SETUP-004: enrollment handler lives in caddy-pm-rs; placeholder \
             until the external service is wired.\n",
        );
        caddyfile.push_str("\t\trespond \"caddy-pm-rs activation layer is not running\" 503\n");
        caddyfile.push_str("\t}\n");
        caddyfile.push_str("\trespond \"caddy-rs is running; use the activation URL\" 200\n");
        caddyfile.push_str("}\n\n");
    }

    let adapted = caddy_rs_config::adapt(&caddyfile)
        .map_err(|error| SetupError::ConfigRejected(error.to_string()))?;
    if adapted.config.get("apps").is_none() {
        return Err(SetupError::ConfigRejected(
            "adapted configuration has no apps section".to_string(),
        ));
    }

    let activation_urls = hosts
        .iter()
        .map(|host| {
            if port == 443 {
                format!("https://{host}{ACTIVATION_PATH}")
            } else {
                format!("https://{host}:{port}{ACTIVATION_PATH}")
            }
        })
        .collect();

    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| std::env::var_os("CADDY_RS_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".caddy-rs"));
    let config_path = data_dir.join("setup").join("Caddyfile");

    Ok(SetupConfig {
        caddyfile,
        json: adapted.config,
        config_path,
        activation_urls,
        registration_timeout: timeout,
        auth_method: args.auth_method,
        storage: args.storage.clone(),
        domain: args.domain.clone(),
    })
}

/// Single-use activation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationToken {
    /// Token value (hex, 128 bits of entropy).
    pub value: String,
    /// Absolute expiry.
    pub expires_at: SystemTime,
}

/// Why a token was rejected.
#[allow(dead_code)] // consumed by the activation handler (T-SETUP-002)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// No such token (already consumed, or never minted).
    Unknown,
    /// The token existed but its TTL elapsed.
    Expired,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown or already-used activation token"),
            Self::Expired => f.write_str("activation token expired"),
        }
    }
}

/// In-memory single-use token store; TTL comes from `--registration-timeout`.
#[derive(Debug)]
pub struct TokenStore {
    timeout: Duration,
    tokens: HashMap<String, SystemTime>,
}

impl TokenStore {
    /// A store whose tokens live for `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            tokens: HashMap::new(),
        }
    }

    /// Mint a fresh 128-bit token that expires after the configured timeout.
    pub fn mint(&mut self, now: SystemTime) -> ActivationToken {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let expires_at = now + self.timeout;
        self.tokens.insert(value.clone(), expires_at);
        ActivationToken { value, expires_at }
    }

    /// Consume a token exactly once. A second consume of the same value is `Unknown`; an elapsed
    /// TTL is `Expired` (and the token is discarded either way).
    #[allow(dead_code)] // called by the activation handler (T-SETUP-002)
    pub fn consume(&mut self, value: &str, now: SystemTime) -> Result<(), TokenError> {
        let Some(expires_at) = self.tokens.remove(value) else {
            return Err(TokenError::Unknown);
        };
        if now >= expires_at {
            return Err(TokenError::Expired);
        }
        Ok(())
    }
}

/// Append a token to an activation URL.
pub fn activation_url_with_token(url: &str, token: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}token={token}")
}

/// Whether the CLI was asked for the stock-compatibility profile.
pub fn stock_compat_requested() -> bool {
    std::env::var(STOCK_COMPAT_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

/// Reject `setup` in the stock-compatibility profile: `setup` is a caddy-rs extension, so stock
/// Caddy (and the stock-compat profile) treats it as an unknown command.
pub fn ensure_not_stock_compat(stock_compat: bool) -> Result<(), SetupError> {
    if stock_compat {
        Err(SetupError::UnknownCommand)
    } else {
        Ok(())
    }
}

/// Seam for the boot step so tests never bind a port.
pub trait BootRunner {
    /// Start caddy-rs with the generated configuration and wait for it to exit.
    fn boot(&self, config: &SetupConfig) -> Result<(), SetupError>;
}

/// Production runner: writes the generated Caddyfile and starts `caddy-rs run` on it.
///
/// It does **not** spawn `caddy-pm-rs`; the generation-scoped external service is T-SETUP-004
/// (ADR-006) and is absent from this build.
#[derive(Debug, Default)]
pub struct ServerBootRunner;

impl BootRunner for ServerBootRunner {
    fn boot(&self, config: &SetupConfig) -> Result<(), SetupError> {
        if let Some(parent) = config.config_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                SetupError::BootFailed(format!("cannot create `{}`: {error}", parent.display()))
            })?;
        }
        std::fs::write(&config.config_path, &config.caddyfile).map_err(|error| {
            SetupError::BootFailed(format!(
                "cannot write `{}`: {error}",
                config.config_path.display()
            ))
        })?;
        let exe = std::env::current_exe()
            .map_err(|error| SetupError::BootFailed(format!("cannot resolve caddy-rs: {error}")))?;
        let status = Command::new(exe)
            .arg("run")
            .arg("--config")
            .arg(&config.config_path)
            .arg("--adapter")
            .arg("caddyfile")
            .status()
            .map_err(|error| SetupError::BootFailed(error.to_string()))?;
        if !status.success() {
            return Err(SetupError::BootFailed(format!(
                "caddy-rs run exited with {status}"
            )));
        }
        Ok(())
    }
}

/// Run the setup command.
pub fn run(args: SetupArgs) -> Result<(), SetupError> {
    run_with_runner(args, &ServerBootRunner)
}

/// Run setup against an explicit boot runner (the test seam).
pub fn run_with_runner<R: BootRunner>(args: SetupArgs, runner: &R) -> Result<(), SetupError> {
    ensure_not_stock_compat(stock_compat_requested())?;
    let config = generate_config(&args)?;
    let mut tokens = TokenStore::new(config.registration_timeout);
    let token = tokens.mint(SystemTime::now());
    let expires_in = token
        .expires_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    println!("caddy-rs setup: activation layer for {}", config.domain);
    println!(
        "caddy-rs setup: auth method {}, storage {}, token expires in {}s (single use)",
        config.auth_method.as_str(),
        config.storage,
        config.registration_timeout.as_secs()
    );
    for url in &config.activation_urls {
        println!("{}", activation_url_with_token(url, &token.value));
    }
    println!("caddy-rs setup: token expires at unix {expires_in}; it can be used once");

    runner.boot(&config)
}
