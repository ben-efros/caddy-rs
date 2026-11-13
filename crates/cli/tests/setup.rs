//! T-SETUP-001: `caddy-rs setup` command surface, generated activation layer, single-use tokens
//! and stock-compat rejection.
//!
//! The boot step is exercised through `setup::BootRunner` with a no-op runner: tests never bind a
//! port and never start a server. The production `ServerBootRunner` (which writes the Caddyfile and
//! runs `caddy-rs run --adapter caddyfile`) is therefore **not** covered by an integration test
//! here; faking a successful boot would not prove anything. The binary is invoked directly only
//! for the stock-compat rejection, which fails before any boot.

#[path = "../src/setup.rs"]
mod setup;

use std::cell::RefCell;
use std::time::{Duration, UNIX_EPOCH};

use clap::{Args, FromArgMatches};
use setup::{
    activation_url_with_token, ensure_not_stock_compat, generate_config, parse_duration,
    run_with_runner, AuthMethod, BootRunner, SetupArgs, SetupConfig, SetupError, TokenError,
    TokenStore,
};

/// Parse `setup` arguments exactly as clap sees them on the command line.
fn parse(argv: &[&str]) -> Result<SetupArgs, clap::Error> {
    let mut full = vec!["setup"];
    full.extend_from_slice(argv);
    let command = <SetupArgs as Args>::augment_args(clap::Command::new("setup"));
    let matches = command.try_get_matches_from(full)?;
    SetupArgs::from_arg_matches(&matches)
}

fn args_with(domain: &str) -> SetupArgs {
    parse(&["--domain", domain]).expect("minimal setup arguments parse")
}

#[test]
fn parses_domain_and_defaults() {
    let args = args_with("example.com");
    assert_eq!(args.domain, "example.com");
    assert_eq!(args.auth_method, AuthMethod::Webauthn);
    assert_eq!(args.storage, "file_system");
    assert_eq!(args.registration_timeout, "15m");
    assert!(args.data_dir.is_none());
    assert!(args.host.is_empty());
    assert!(args.listen_address.is_none());
    assert!(!args.acme);
    assert!(!args.cloudflare);
    assert!(args.cf_api_token.is_none());
}

#[test]
fn requires_domain() {
    let error = parse(&[]).expect_err("--domain is required");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
}

#[test]
fn parses_each_documented_flag() {
    let args = parse(&[
        "--domain",
        "example.com",
        "--auth-method",
        "totp",
        "--storage",
        "redis",
        "--registration-timeout",
        "30m",
        "--data-dir",
        "/tmp/caddy-rs-setup",
        "--host",
        "alt.example.com",
        "--host",
        "alt2.example.com",
        "--listen-address",
        "127.0.0.1:8443",
        "--acme",
        "--cloudflare",
        "--cf-api-token",
        "/run/secrets/cf",
    ])
    .expect("all documented flags parse");
    assert_eq!(args.domain, "example.com");
    assert_eq!(args.auth_method, AuthMethod::Totp);
    assert_eq!(args.storage, "redis");
    assert_eq!(args.registration_timeout, "30m");
    assert_eq!(
        args.data_dir.as_deref(),
        Some(std::path::Path::new("/tmp/caddy-rs-setup"))
    );
    assert_eq!(args.host, ["alt.example.com", "alt2.example.com"]);
    assert_eq!(args.listen_address.as_deref(), Some("127.0.0.1:8443"));
    assert!(args.acme);
    assert!(args.cloudflare);
    assert_eq!(args.cf_api_token.as_deref(), Some("/run/secrets/cf"));
}

#[test]
fn rejects_unknown_flag() {
    assert!(parse(&["--domain", "example.com", "--nope"]).is_err());
}

#[test]
fn generated_config_contains_activation_layer_and_domain() {
    let args = args_with("example.com");
    let config = generate_config(&args).expect("config generates");
    assert!(config.caddyfile.contains("temporary activation layer"));
    assert!(config.caddyfile.contains("/_caddy-pm/activate"));
    assert!(config.caddyfile.contains("example.com"));
    assert_eq!(config.domain, "example.com");
    assert_eq!(config.registration_timeout, Duration::from_secs(15 * 60));
    assert_eq!(
        config.activation_urls,
        vec!["https://example.com/_caddy-pm/activate"]
    );
    // The adapter accepted the generated Caddyfile and produced an http app.
    assert!(config.json.get("apps").is_some());
    assert!(config
        .json
        .get("apps")
        .and_then(|apps| apps.get("http"))
        .is_some());
    assert!(config.config_path.ends_with("setup/Caddyfile"));
}

#[test]
fn generated_config_uses_each_host_and_auth_method() {
    let args = parse(&[
        "--domain",
        "example.com",
        "--host",
        "alt.example.com",
        "--auth-method",
        "totp",
    ])
    .expect("args parse");
    let config = generate_config(&args).expect("config generates");
    assert!(config.caddyfile.contains("auth: totp"));
    assert!(config.caddyfile.contains("alt.example.com"));
    assert_eq!(
        config.activation_urls,
        vec![
            "https://example.com/_caddy-pm/activate",
            "https://alt.example.com/_caddy-pm/activate"
        ]
    );
}

#[test]
fn generated_config_uses_listen_port() {
    let args =
        parse(&["--domain", "example.com", "--listen-address", ":8443"]).expect("args parse");
    let config = generate_config(&args).expect("config generates");
    assert!(config.caddyfile.contains("example.com:8443"));
    assert_eq!(
        config.activation_urls,
        vec!["https://example.com:8443/_caddy-pm/activate"]
    );
}

#[test]
fn rejects_invalid_domain_and_storage_and_timeout() {
    let mut args = args_with("bad domain");
    assert!(matches!(
        generate_config(&args),
        Err(SetupError::InvalidDomain(_))
    ));

    args = args_with("example.com");
    args.storage = "sqlite".to_string();
    assert!(matches!(
        generate_config(&args),
        Err(SetupError::InvalidStorage(_))
    ));

    args = args_with("example.com");
    args.registration_timeout = "1m".to_string();
    assert!(matches!(
        generate_config(&args),
        Err(SetupError::InvalidRegistrationTimeout(_))
    ));

    args.registration_timeout = "2h".to_string();
    assert!(matches!(
        generate_config(&args),
        Err(SetupError::InvalidRegistrationTimeout(_))
    ));
}

#[test]
fn parses_duration_forms() {
    assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
    assert_eq!(parse_duration("900s").unwrap(), Duration::from_secs(900));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert!(parse_duration("15x").is_err());
}

#[test]
fn token_is_single_use() {
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut store = TokenStore::new(Duration::from_secs(900));
    let token = store.mint(now);
    assert_eq!(token.value.len(), 32, "128-bit hex token");
    assert_eq!(token.expires_at, now + Duration::from_secs(900));

    assert_eq!(
        store.consume(&token.value, now + Duration::from_secs(1)),
        Ok(())
    );
    assert_eq!(
        store.consume(&token.value, now + Duration::from_secs(2)),
        Err(TokenError::Unknown),
        "a second consume of the same token must fail"
    );
}

#[test]
fn token_expires_after_registration_timeout() {
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut store = TokenStore::new(Duration::from_secs(900));
    let token = store.mint(now);
    assert_eq!(
        store.consume(&token.value, now + Duration::from_secs(900)),
        Err(TokenError::Expired)
    );
    // Expired tokens are discarded too.
    assert_eq!(
        store.consume(&token.value, now + Duration::from_secs(901)),
        Err(TokenError::Unknown)
    );
    assert_eq!(store.consume("deadbeef", now), Err(TokenError::Unknown));
}

#[test]
fn activation_url_carries_token() {
    assert_eq!(
        activation_url_with_token("https://example.com/_caddy-pm/activate", "abc"),
        "https://example.com/_caddy-pm/activate?token=abc"
    );
}

#[test]
fn stock_compat_rejects_setup_as_unknown_command() {
    let error = ensure_not_stock_compat(true).expect_err("stock_compat must reject setup");
    assert!(matches!(error, SetupError::UnknownCommand));
    let message = error.to_string();
    assert!(message.contains("unknown command"), "{message}");
    assert!(message.contains("setup"), "{message}");
    assert_eq!(ensure_not_stock_compat(false), Ok(()));
}

#[test]
fn stock_compat_binary_rejects_setup_before_boot() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_caddy-rs"))
        .args(["setup", "--domain", "example.com"])
        .env(setup::STOCK_COMPAT_ENV, "true")
        .output()
        .expect("caddy-rs binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown command"), "{stderr}");
    assert!(stderr.contains("setup"), "{stderr}");
}

struct NoopRunner {
    booted: RefCell<Option<SetupConfig>>,
}

impl BootRunner for NoopRunner {
    fn boot(&self, config: &SetupConfig) -> Result<(), SetupError> {
        *self.booted.borrow_mut() = Some(config.clone());
        Ok(())
    }
}

#[test]
fn run_uses_boot_seam_without_binding_ports() {
    let temp = tempfile::tempdir().expect("tempdir");
    let args = parse(&[
        "--domain",
        "example.com",
        "--data-dir",
        temp.path().to_str().expect("utf-8 temp path"),
    ])
    .expect("args parse");
    let runner = NoopRunner {
        booted: RefCell::new(None),
    };
    run_with_runner(args, &runner).expect("no-op boot succeeds");
    let config = runner.booted.borrow();
    let config = config.as_ref().expect("boot runner received the config");
    assert!(config.caddyfile.contains("temporary activation layer"));
    assert_eq!(config.activation_urls.len(), 1);
    // No-op runner: the Caddyfile was not written and no listener was started.
    assert!(!config.config_path.exists());
}
