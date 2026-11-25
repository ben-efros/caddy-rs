//! `caddy-rs setup` — zero-config first-boot authentication bootstrap (T-SETUP-001).
//!
//! Scope of this task is the command surface and the generated configuration: flags, a temporary
//! activation layer, single-use activation tokens, and the boot seam. The activation handler
//! itself (T-SETUP-002), WebAuthn/TOTP enrollment (T-SETUP-003) and the generation-scoped
//! `caddy-pm-rs` external service (T-SETUP-004, ADR-006) are not part of this task; the generated
//! route is therefore a placeholder `respond` handler.
//!
//! The generation-scoped `caddy-pm-rs` service is T-SETUP-004 and IS wired here: [`SetupService`]
//! is resolved and started before the boot, tagged with the configuration generation, and stopped
//! on handoff so a normal run proceeds without it. The plan and ADRs call the service
//! `caddy-pm-rs`, but the binary the `pm` workspace actually builds is `caddy-rs-pm`
//! (`pm/crates/pm-cli/Cargo.toml`, `[[bin]] name = "caddy-rs-pm"`); both names are accepted when
//! resolving it, so neither spelling is a trap.
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

impl Default for SetupArgs {
    /// Every flag at its documented default, with an empty `--domain`.
    ///
    /// `--domain` is required on the command line, so there is no "valid" default for it; this
    /// exists so a caller or test that only cares about one or two flags does not have to spell
    /// out the rest. `generate_config` still rejects the empty domain with a located error.
    fn default() -> Self {
        Self {
            domain: String::new(),
            auth_method: AuthMethod::Webauthn,
            storage: "file_system".to_string(),
            registration_timeout: "15m".to_string(),
            data_dir: None,
            host: Vec::new(),
            listen_address: None,
            acme: false,
            cloudflare: false,
            cf_api_token: None,
        }
    }
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
    /// The `caddy-pm-rs` service binary could not be found or would not start.
    ServiceUnavailable(String),
    /// The activation endpoint's certificate could not be issued or loaded (T-SETUP-008).
    TlsUnavailable(String),
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
            Self::ServiceUnavailable(reason) => {
                write!(f, "caddy-pm-rs service is unavailable: {reason}")
            }
            Self::TlsUnavailable(reason) => {
                write!(f, "cannot serve the activation endpoint over TLS: {reason}")
            }
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
    /// Listener the activation endpoint binds (`host:port`, TLS with the internal CA cert).
    pub activation_listen: String,
    /// Enrollment method.
    pub auth_method: AuthMethod,
    /// Storage backend requested by the operator.
    pub storage: String,
    /// Primary domain.
    pub domain: String,
    /// Every site host, `--domain` first and duplicates dropped: the names the activation
    /// certificate must cover and the names the activation URLs are printed for.
    pub hosts: Vec<String>,
    /// Data directory for this boot (T-SETUP-006). Passed to `caddy-rs run` and to the
    /// `caddy-rs-pm` service so neither falls back to `/var/lib/caddy-rs`.
    pub data_dir: PathBuf,
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

/// The default port an ADR-0039 listen address uses when it names none.
pub const DEFAULT_LISTEN_PORT: u16 = 443;

/// A parsed ADR-0039 `--listen-address`.
///
/// The flag accepts `IP`, `IP:port`, `[IPv6]`, `[IPv6]:port` or `:port` (ADR-0039). The address and
/// the port are kept *separately*: keeping only the port was the T-SETUP-007 defect, which made
/// `--listen-address 127.0.0.1:18443` bind every interface. `None` means "no address given", which
/// resolves to loopback (see [`SetupListen::default`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupListen {
    /// The literal address to bind, or `None` for a host-less `:port` (all interfaces).
    pub ip: Option<std::net::IpAddr>,
    /// The port to bind.
    pub port: u16,
}

impl Default for SetupListen {
    /// No `--listen-address`: loopback, port 443.
    ///
    /// Loopback rather than the wildcard because the activation endpoint carries a live
    /// single-use credential and is reachable over TLS only after the operator has the fingerprint
    /// to compare it against; binding it everywhere by default would publish the claim window
    /// before anyone has verified what they are talking to.
    fn default() -> Self {
        Self {
            ip: Some(std::net::IpAddr::from([127, 0, 0, 1])),
            port: DEFAULT_LISTEN_PORT,
        }
    }
}

impl SetupListen {
    /// Parse `--listen-address`, or return the loopback default when the flag is absent.
    ///
    /// An address that names an IP is bound to exactly that IP. A host-less `:port` is the one
    /// documented spelling that means every interface (ADR-0039), and it is the only way to get
    /// that: no explicit IP is ever widened to the wildcard.
    pub fn parse(addr: Option<&str>) -> Result<Self, SetupError> {
        let Some(addr) = addr else {
            return Ok(Self::default());
        };
        let invalid = || SetupError::InvalidListenAddress(addr.to_string());
        if addr.is_empty() || addr.contains(char::is_whitespace) {
            return Err(invalid());
        }
        // Host-less `:port`: all interfaces, the ADR-0039 spelling for it.
        if let Some(port) = addr.strip_prefix(':') {
            return Ok(Self {
                ip: None,
                port: parse_port(port).ok_or_else(invalid)?,
            });
        }
        // Bracketed IPv6: `[IPv6]` or `[IPv6]:port`. Unbracketed IPv6 is rejected rather than
        // guessed at, because `2001:db8::1:8443` cannot be split into address and port unambiguously.
        if let Some(rest) = addr.strip_prefix('[') {
            let (literal, after) = rest.split_once(']').ok_or_else(invalid)?;
            let ip: std::net::IpAddr = literal.parse().map_err(|_| invalid())?;
            if !ip.is_ipv6() {
                return Err(invalid());
            }
            let port = match after {
                "" => DEFAULT_LISTEN_PORT,
                after => {
                    parse_port(after.strip_prefix(':').ok_or_else(invalid)?).ok_or_else(invalid)?
                }
            };
            return Ok(Self { ip: Some(ip), port });
        }
        // `IP` or `IP:port`. A bare IPv4 literal has no port; anything else must split cleanly.
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            return Ok(Self {
                ip: Some(ip),
                port: DEFAULT_LISTEN_PORT,
            });
        }
        let (host, port) = addr.rsplit_once(':').ok_or_else(invalid)?;
        let ip: std::net::IpAddr = host.parse().map_err(|_| invalid())?;
        Ok(Self {
            ip: Some(ip),
            port: parse_port(port).ok_or_else(invalid)?,
        })
    }

    /// The port only, for the generated site address and the activation URL.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The concrete `host:port` the activation listener binds.
    ///
    /// A host-less `:port` binds `0.0.0.0` — every interface — because that is what the spelling
    /// means; every form that names an address binds exactly that address.
    pub fn bind_address(&self) -> String {
        match self.ip {
            Some(ip) => std::net::SocketAddr::new(ip, self.port).to_string(),
            None => std::net::SocketAddr::from(([0, 0, 0, 0], self.port)).to_string(),
        }
    }
}

/// Parse a decimal port, rejecting empty strings and values above `u16::MAX`.
fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse().ok()
}

/// The concrete `host:port` the activation endpoint binds (T-SETUP-007).
///
/// `port` is the port resolved from the same address by [`SetupListen::parse`]; it is accepted so a
/// caller holding both halves cannot pass a mismatched pair, and it must agree with the address's
/// own port (the parser never produces a different one).
pub fn activation_listen(addr: Option<&str>, port: u16) -> String {
    let listen = SetupListen::parse(addr).unwrap_or_default();
    let listen = SetupListen { port, ..listen };
    listen.bind_address()
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
    let listen = SetupListen::parse(args.listen_address.as_deref())?;
    let port = listen.port();
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

    let data_dir = resolve_data_dir(args);
    let config_path = data_dir.join("setup").join("Caddyfile");

    Ok(SetupConfig {
        caddyfile,
        json: adapted.config,
        config_path,
        activation_urls,
        activation_listen: listen.bind_address(),
        registration_timeout: timeout,
        auth_method: args.auth_method,
        storage: args.storage.clone(),
        domain: args.domain.clone(),
        hosts,
        data_dir,
    })
}

/// The data directory a setup boot uses: `--data-dir`, else `$CADDY_RS_DATA_DIR`, else
/// `./.caddy-rs`.
///
/// Resolved in one place because three consumers need the same answer (the generated Caddyfile's
/// path, the `caddy-rs run` child and the `caddy-rs-pm` service); resolving it separately in each
/// is how `--data-dir` came to reach the first and not the other two (T-SETUP-006).
pub fn resolve_data_dir(args: &SetupArgs) -> PathBuf {
    args.data_dir
        .clone()
        .or_else(|| std::env::var_os("CADDY_RS_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".caddy-rs"))
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

/// The binary names the `caddy-pm-rs` service is known by, in resolution order.
///
/// The plan and ADRs call it `caddy-pm-rs`; the `pm` workspace builds `caddy-rs-pm`. Accepting both
/// means an operator who installs either name gets a working setup, and the "missing binary" error
/// (acceptance criterion 3) only fires when neither exists.
pub const SERVICE_BINARY_NAMES: &[&str] = &["caddy-pm-rs", "caddy-rs-pm"];

/// Environment variable that pins the service binary path, bypassing the search.
pub const SERVICE_BIN_ENV: &str = "CADDY_RS_PM_BIN";

/// How the `caddy-pm-rs` service is located and started.
///
/// This is a trait for the same reason [`BootRunner`] is one: a test must be able to prove the
/// service is started, generation-scoped and stopped without spawning a real process or binding a
/// port. [`ProcessService`] is the production implementation.
pub trait ServiceSupervisor {
    /// Resolve and start the service for configuration generation `generation`, with its data
    /// directory at `data_dir`.
    ///
    /// `data_dir` is a parameter rather than ambient state because it is the one thing the
    /// service cannot infer: its own default is `/var/lib/caddy-rs`, which is read-only on a
    /// hardened host and is not where `setup` was told to write (T-SETUP-006).
    fn start(&self, generation: u64, data_dir: &std::path::Path) -> Result<(), SetupError>;

    /// Stop the service. Idempotent, and must succeed when nothing was started.
    fn stop(&self) -> Result<(), SetupError>;
}

/// The generation-scoped `caddy-pm-rs` service for one setup boot.
///
/// The service is scoped to the *configuration generation*, not to the process or to wall-clock
/// time: it is started with the generation id in its environment and is expected to serve only
/// that generation's requests. The setup boot is generation 1 — the temporary activation layer —
/// and the handoff to a normal run ends that generation, so the service is stopped rather than
/// inherited. Keeping the id explicit is what makes "scoped to the generation" checkable instead
/// of implied.
#[derive(Debug)]
pub struct SetupService<S: ServiceSupervisor> {
    supervisor: S,
    generation: u64,
    data_dir: PathBuf,
    started: std::cell::Cell<bool>,
}

/// The generation id of the setup boot's temporary activation layer.
pub const SETUP_GENERATION: u64 = 1;

impl<S: ServiceSupervisor> SetupService<S> {
    /// Create the service for `generation`, writing under `data_dir`. Nothing is started yet.
    pub fn new(supervisor: S, generation: u64, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            supervisor,
            generation,
            data_dir: data_dir.into(),
            started: std::cell::Cell::new(false),
        }
    }

    /// The data directory the service is started with.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// The configuration generation this service is scoped to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Start the service for this generation. Starting twice is a no-op, so a retried boot does not
    /// leak a second service.
    pub fn start(&self) -> Result<(), SetupError> {
        if self.started.get() {
            return Ok(());
        }
        self.supervisor.start(self.generation, &self.data_dir)?;
        self.started.set(true);
        Ok(())
    }

    /// Stop the service. Safe to call when it was never started, so the handoff path cannot fail
    /// merely because the boot failed early.
    pub fn stop(&self) -> Result<(), SetupError> {
        if !self.started.get() {
            return Ok(());
        }
        self.supervisor.stop()?;
        self.started.set(false);
        Ok(())
    }
}

/// Production supervisor: runs the service binary as a child process.
///
/// The child is started with `CADDY_RS_PM_GENERATION` set to the generation id, which is how the
/// service knows which configuration generation it is serving. `stop` kills and reaps the child, so
/// the handoff leaves no orphan behind.
#[derive(Debug, Default)]
pub struct ProcessService {
    child: std::sync::Mutex<Option<std::process::Child>>,
}

impl ProcessService {
    /// Locate the service binary: `CADDY_RS_PM_BIN` if set, else the first of
    /// [`SERVICE_BINARY_NAMES`] found next to the current executable or on `PATH`.
    pub fn resolve_binary() -> Result<std::path::PathBuf, SetupError> {
        if let Some(pinned) = std::env::var_os(SERVICE_BIN_ENV) {
            let path = std::path::PathBuf::from(&pinned);
            if path.is_file() {
                return Ok(path);
            }
            return Err(SetupError::ServiceUnavailable(format!(
                "{SERVICE_BIN_ENV} points at `{}`, which is not a file",
                path.display()
            )));
        }
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
        for name in SERVICE_BINARY_NAMES {
            if let Some(dir) = &exe_dir {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
            if let Some(path) = find_on_path(name) {
                return Ok(path);
            }
        }
        Err(SetupError::ServiceUnavailable(format!(
            "no `caddy-pm-rs` service binary found: looked for {} next to `{}` and on PATH; \
             install it or set {SERVICE_BIN_ENV}",
            SERVICE_BINARY_NAMES.join("` / `"),
            exe_dir
                .as_deref()
                .map_or_else(|| "<unknown>".to_string(), |d| d.display().to_string()),
        )))
    }
}

/// Search `PATH` for an executable named `name`.
fn find_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

impl ServiceSupervisor for ProcessService {
    fn start(&self, generation: u64, data_dir: &std::path::Path) -> Result<(), SetupError> {
        let binary = Self::resolve_binary()?;
        // `caddy-rs-pm`'s data directory is the global `--data-dir` option, which also reads
        // `PM_DATA_DIR`. Both are set, and deliberately so:
        //
        // * the flag is the contract — `pm/crates/pm-cli` parses `--data-dir` as a *global* option
        //   (it must precede `serve`; `serve --data-dir` is a clap error, which systemd reports as
        //   a failed start), so passing it here matches what the generated systemd unit does;
        // * the environment variable covers a future `caddy-rs-pm` build whose argument order
        //   differs, and is what an operator would set by hand.
        //
        // Without this the service ignores `caddy-rs setup --data-dir` and defaults to
        // `/var/lib/caddy-rs`, which fails on a read-only filesystem (T-SETUP-006).
        let child = Command::new(&binary)
            .arg("--data-dir")
            .arg(data_dir)
            .arg("serve")
            .env("PM_DATA_DIR", data_dir)
            .env("CADDY_RS_PM_GENERATION", generation.to_string())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|error| {
                SetupError::ServiceUnavailable(format!(
                    "cannot start `{}`: {error}",
                    binary.display()
                ))
            })?;
        *self.child.lock().expect("service mutex") = Some(child);
        Ok(())
    }

    fn stop(&self) -> Result<(), SetupError> {
        let mut slot = self.child.lock().expect("service mutex");
        let Some(mut child) = slot.take() else {
            return Ok(());
        };
        // `kill` fails if the child already exited; that is not an error, the goal is "not running".
        let _ = child.kill();
        child.wait().map_err(|error| {
            SetupError::ServiceUnavailable(format!("cannot reap the caddy-pm-rs service: {error}"))
        })?;
        Ok(())
    }
}

/// Start the service for its generation, run `boot`, then stop the service on handoff.
///
/// The ordering is the contract, so it lives in one place rather than being re-implemented by its
/// tests:
///
/// 1. **start first** — the activation layer is useless without the enrollment handler the service
///    provides, so a missing binary must be a located error rather than a boot that comes up
///    serving 503 (criterion 3);
/// 2. **stop on handoff regardless of outcome** — a normal run must not inherit the setup service,
///    and a failed boot must not leak it (criterion 1).
///
/// The boot error wins over a stop error: it is what the operator needs to see first, and the
/// service is already stopped either way.
fn run_service_around_boot<S: ServiceSupervisor, T>(
    service: &SetupService<S>,
    boot: impl FnOnce(T) -> Result<(), SetupError>,
) -> Result<(), SetupError>
where
    T: Default,
{
    service.start()?;
    let boot_result = boot(T::default());
    let stop_result = service.stop();
    boot_result?;
    stop_result
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
#[derive(Debug)]
pub struct ServiceBootRunner<S: ServiceSupervisor> {
    service: Option<SetupService<S>>,
}

/// The production boot runner: [`ServiceBootRunner`] over the real [`ProcessService`].
pub type ServerBootRunner = ServiceBootRunner<ProcessService>;

impl ServiceBootRunner<ProcessService> {
    /// Build the runner with a generation-scoped `caddy-pm-rs` service. `Default` has no service,
    /// which keeps `boot` usable where no proxy manager is installed.
    pub fn with_service(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            service: Some(SetupService::new(
                ProcessService::default(),
                SETUP_GENERATION,
                data_dir,
            )),
        }
    }
}

impl<S: ServiceSupervisor> Default for ServiceBootRunner<S> {
    fn default() -> Self {
        Self { service: None }
    }
}

impl<S: ServiceSupervisor> ServiceBootRunner<S> {
    /// Build a runner over an explicit supervisor (the test seam for the handoff behaviour).
    pub fn with_supervisor(supervisor: S, generation: u64, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            service: Some(SetupService::new(supervisor, generation, data_dir)),
        }
    }
}

impl<S: ServiceSupervisor> BootRunner for ServiceBootRunner<S> {
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
        match &self.service {
            Some(service) => run_service_around_boot(service, |()| self.run_caddy(config)),
            None => self.run_caddy(config),
        }
    }
}

impl<S: ServiceSupervisor> ServiceBootRunner<S> {
    /// Start `caddy-rs run` on the generated configuration and wait for it to exit.
    fn run_caddy(&self, config: &SetupConfig) -> Result<(), SetupError> {
        let exe = std::env::current_exe()
            .map_err(|error| SetupError::BootFailed(format!("cannot resolve caddy-rs: {error}")))?;
        let status = Command::new(exe)
            .arg("run")
            .arg("--config")
            .arg(&config.config_path)
            .arg("--adapter")
            .arg("caddyfile")
            // T-SETUP-006: the child must write where `setup --data-dir` said, not to the default.
            .arg("--data-dir")
            .arg(&config.data_dir)
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
    let data_dir = resolve_data_dir(&args);
    run_with_runner(args, &ServerBootRunner::with_service(data_dir))
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

#[cfg(test)]
mod t_setup_004_tests {
    //! T-SETUP-004: the generation-scoped `caddy-pm-rs` service — started for a setup boot,
    //! scoped to the configuration generation, stopped on handoff, and a located error when the
    //! binary is missing.
    //!
    //! These tests never call `boot` itself: `run_caddy` re-executes `current_exe()` as `caddy-rs
    //! run`, which under `cargo test` is the test binary, so driving the real boot would recurse
    //! into the test suite. The ordering contract is instead exercised through
    //! `run_service_around_boot`, which is the same function `boot` delegates to — so the
    //! production path and these tests cannot drift apart.

    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    /// Serialises tests that mutate process-global environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// The data directory the recording-supervisor tests are started with.
    const DATA_DIR: &str = "/nonexistent/t-setup-data";

    #[derive(Debug, Default)]
    struct RecordingSupervisor {
        log: RefCell<Vec<String>>,
        fail_start: bool,
    }

    impl ServiceSupervisor for RecordingSupervisor {
        fn start(&self, generation: u64, data_dir: &std::path::Path) -> Result<(), SetupError> {
            if self.fail_start {
                return Err(SetupError::ServiceUnavailable("no binary".to_string()));
            }
            self.log
                .borrow_mut()
                .push(format!("start({generation},{})", data_dir.display()));
            Ok(())
        }

        fn stop(&self) -> Result<(), SetupError> {
            self.log.borrow_mut().push("stop".to_string());
            Ok(())
        }
    }

    /// Lets a test observe a supervisor the service owns.
    struct Shared(Arc<RecordingSupervisor>);

    impl ServiceSupervisor for Shared {
        fn start(&self, generation: u64, data_dir: &std::path::Path) -> Result<(), SetupError> {
            self.0.start(generation, data_dir)
        }
        fn stop(&self) -> Result<(), SetupError> {
            self.0.stop()
        }
    }

    #[test]
    fn the_service_is_scoped_to_the_setup_generation() {
        let supervisor = Arc::new(RecordingSupervisor::default());
        let service = SetupService::new(Shared(supervisor.clone()), SETUP_GENERATION, DATA_DIR);
        assert_eq!(service.generation(), SETUP_GENERATION);
        run_service_around_boot(&service, |()| Ok(())).expect("boot");
        assert_eq!(
            supervisor.log.borrow()[0],
            format!("start({SETUP_GENERATION},{DATA_DIR})"),
            "the service must be started for the setup configuration generation, not generation 0"
        );
    }

    #[test]
    fn the_service_is_stopped_on_handoff_when_the_boot_succeeds() {
        // Criterion 1's second half. My first round of tests did not cover it: deleting the stop
        // call left all of them green.
        let supervisor = Arc::new(RecordingSupervisor::default());
        let service = SetupService::new(Shared(supervisor.clone()), SETUP_GENERATION, DATA_DIR);
        run_service_around_boot(&service, |()| Ok(())).expect("boot");
        assert_eq!(
            *supervisor.log.borrow(),
            vec![
                format!("start({SETUP_GENERATION},{DATA_DIR})"),
                "stop".to_string()
            ],
            "start -> stop around a successful boot"
        );
    }

    #[test]
    fn the_service_is_stopped_on_handoff_when_the_boot_fails() {
        // A failed boot must not leak the service.
        let supervisor = Arc::new(RecordingSupervisor::default());
        let service = SetupService::new(Shared(supervisor.clone()), SETUP_GENERATION, DATA_DIR);
        let result = run_service_around_boot(&service, |()| {
            Err(SetupError::BootFailed("simulated".to_string()))
        });
        assert!(result.is_err(), "the boot failure propagates");
        assert_eq!(
            *supervisor.log.borrow(),
            vec![
                format!("start({SETUP_GENERATION},{DATA_DIR})"),
                "stop".to_string()
            ],
            "the service must still be stopped after a failed boot"
        );
    }

    #[test]
    fn a_missing_service_binary_aborts_before_the_boot_runs() {
        // Criterion 3, plus the ordering half: the service starts first, so a missing binary is a
        // located error rather than a boot that comes up serving 503.
        let service = SetupService::new(
            RecordingSupervisor {
                fail_start: true,
                ..Default::default()
            },
            SETUP_GENERATION,
            DATA_DIR,
        );
        let booted = std::cell::Cell::new(false);
        let error = run_service_around_boot(&service, |()| {
            booted.set(true);
            Ok(())
        })
        .expect_err("a missing binary must fail the setup boot");
        let text = error.to_string();
        assert!(matches!(error, SetupError::ServiceUnavailable(_)), "{text}");
        assert!(text.contains("caddy-pm-rs"), "names the service: {text}");
        assert!(!booted.get(), "the boot must not run without the service");
    }

    #[test]
    fn starting_twice_does_not_leak_a_second_service() {
        let supervisor = Arc::new(RecordingSupervisor::default());
        let service = SetupService::new(Shared(supervisor.clone()), 1, DATA_DIR);
        service.start().expect("start");
        service.start().expect("start again");
        assert_eq!(
            supervisor.log.borrow().len(),
            1,
            "a retried boot must not start a second service"
        );
    }

    #[test]
    fn stop_is_idempotent_and_safe_when_never_started() {
        let supervisor = Arc::new(RecordingSupervisor::default());
        let service = SetupService::new(Shared(supervisor.clone()), 1, DATA_DIR);
        service.stop().expect("stop before start");
        assert!(supervisor.log.borrow().is_empty(), "nothing to stop");

        service.start().expect("start");
        service.stop().expect("stop");
        service.stop().expect("stop again");
        assert_eq!(
            *supervisor.log.borrow(),
            vec![format!("start(1,{DATA_DIR})"), "stop".to_string()],
            "stop must not double-stop the service"
        );
    }

    #[test]
    fn process_service_names_the_pinned_path_and_the_escape_hatch() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let missing = "/nonexistent/caddy-pm-rs-for-t-setup-004";
        // SAFETY: the ENV_LOCK guard serialises this against the other env test.
        unsafe { std::env::set_var(SERVICE_BIN_ENV, missing) };
        let result = ProcessService::resolve_binary();
        unsafe { std::env::remove_var(SERVICE_BIN_ENV) };

        let text = result.expect_err("pinned path does not exist").to_string();
        assert!(text.contains(missing), "names the pinned path: {text}");
        assert!(
            text.contains(SERVICE_BIN_ENV),
            "names the escape hatch: {text}"
        );
    }

    #[test]
    fn a_missing_binary_message_names_both_accepted_spellings() {
        // With no pin and no PATH entry, the resolver's error must tell the operator what it
        // looked for. Clearing PATH under the lock keeps this hermetic.
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved = std::env::var_os("PATH");
        let saved_bin = std::env::var_os(SERVICE_BIN_ENV);
        // SAFETY: serialised by ENV_LOCK; both variables are restored below.
        unsafe {
            std::env::remove_var(SERVICE_BIN_ENV);
            std::env::set_var("PATH", "");
        }
        let result = ProcessService::resolve_binary();
        unsafe {
            match saved {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
            if let Some(value) = saved_bin {
                std::env::set_var(SERVICE_BIN_ENV, value);
            }
        }

        let text = result
            .expect_err("no service binary on an empty PATH")
            .to_string();
        for name in SERVICE_BINARY_NAMES {
            assert!(text.contains(name), "must name `{name}`: {text}");
        }
        assert!(
            text.contains(SERVICE_BIN_ENV),
            "names the escape hatch: {text}"
        );
    }

    #[test]
    fn both_service_binary_names_are_accepted() {
        // The plan says `caddy-pm-rs`; the pm workspace builds `caddy-rs-pm`. Neither may be a trap.
        assert!(SERVICE_BINARY_NAMES.contains(&"caddy-pm-rs"));
        assert!(SERVICE_BINARY_NAMES.contains(&"caddy-rs-pm"));
    }

    #[test]
    fn a_runner_without_a_service_boots_without_one() {
        // `Default` keeps the old behaviour available where no proxy manager is installed.
        assert!(ServiceBootRunner::<RecordingSupervisor>::default()
            .service
            .is_none());
    }
}
