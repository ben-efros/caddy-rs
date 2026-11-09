//! Optional integration check against a built `caddy-rs` binary.
//!
//! The unit tests never require the binary. These tests look for the canonical debug build (or a
//! path in `CADDY_RS_BIN`) and skip with a diagnostic when it is absent, so an offline checkout can
//! still run `cargo test --workspace`.

use std::path::PathBuf;
use std::process::Command;

use caddy_rs_pm_config::{assemble_from_hosts, ConfigSettings};
use caddy_rs_pm_core::{
    Host, HostId, HostSpec, HostTls, PolicyId, ProxySpec, Upstream, UpstreamScheme,
};
use serde_json::Value;

const DEFAULT_CADDY_RS: &str = "/root/caddy-rs/.scratch/rust-target/debug/caddy-rs";

fn caddy_rs_binary() -> Option<PathBuf> {
    let candidate = std::env::var_os("CADDY_RS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CADDY_RS));
    if candidate.is_file() {
        Some(candidate)
    } else {
        eprintln!(
            "skipping caddy-rs validation: binary not found at {} (set CADDY_RS_BIN to override)",
            candidate.display()
        );
        None
    }
}

fn validate_with_caddy(config: &Value) {
    let Some(binary) = caddy_rs_binary() else {
        return;
    };

    let file = tempfile::Builder::new()
        .prefix("pm-config-")
        .suffix(".json")
        .tempfile()
        .expect("create temp config");
    std::fs::write(file.path(), config.to_string()).expect("write temp config");

    let output = Command::new(&binary)
        .arg("validate")
        .arg("--config")
        .arg(file.path())
        .arg("--adapter")
        .arg("json")
        .output()
        .expect("run caddy-rs validate");

    assert!(
        output.status.success(),
        "caddy-rs validate rejected the assembled config\nstdout:\n{}\nstderr:\n{}\nconfig:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        serde_json::to_string_pretty(config).expect("serialize config")
    );
    eprintln!(
        "caddy-rs validate accepted {}: {}",
        file.path().display(),
        String::from_utf8_lossy(&output.stdout).trim()
    );
}

fn proxy_host(id: u64, domain: &str, tls: HostTls) -> Host {
    Host::new(
        HostId(id),
        vec![domain.to_string()],
        tls,
        HostSpec::Proxy(ProxySpec::new(Upstream::new(
            UpstreamScheme::Http,
            "10.0.0.5",
            8080,
        ))),
    )
}

#[test]
fn empty_assembled_config_is_accepted() {
    let config =
        assemble_from_hosts(&[], &ConfigSettings::default()).expect("assemble empty config");
    validate_with_caddy(&config);
}

#[test]
fn simple_proxy_assembled_config_is_accepted() {
    let hosts = vec![proxy_host(1, "example.com", HostTls::disabled())];
    let config = assemble_from_hosts(&hosts, &ConfigSettings::default()).expect("assemble");
    validate_with_caddy(&config);
}

#[test]
fn custom_ports_and_tls_routes_are_accepted() {
    let hosts = vec![proxy_host(
        2,
        "secure.example.com",
        HostTls::for_auto(PolicyId(4)),
    )];
    let config = assemble_from_hosts(&hosts, &ConfigSettings::new(8080, 8443)).expect("assemble");
    validate_with_caddy(&config);
}
