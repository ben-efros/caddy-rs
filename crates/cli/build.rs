//! Captures the toolchain facts Caddy obtains from `runtime/debug.ReadBuildInfo` at runtime.
//!
//! Rust does not expose its compiler version or target triple from the standard library, so the
//! `build-info` and `environ` commands read these values baked in by Cargo here. `cargo test
//! --offline --locked` runs this script; it only invokes the already-selected `rustc`, never the
//! network.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = Command::new(&rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    // Cargo sets PROFILE to `debug` or `release` for build scripts. Custom profiles still fall
    // back to one of those two debug-assertion-based buckets.
    let profile = std::env::var("PROFILE")
        .ok()
        .filter(|profile| !profile.is_empty())
        .unwrap_or_else(|| {
            if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            }
        });

    println!("cargo:rustc-env=CADDY_RS_BUILD_RUSTC={rustc_version}");
    println!("cargo:rustc-env=CADDY_RS_BUILD_TARGET={target}");
    println!("cargo:rustc-env=CADDY_RS_BUILD_PROFILE={profile}");
}
