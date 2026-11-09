//! `build-info`: the Rust translation of Caddy's `debug.ReadBuildInfo()` dump.
//!
//! Caddy's command prints the Go build-info struct verbatim: a `go` toolchain line, `path`/`mod`
//! module lines, and tab-separated `build` settings. Rust has no equivalent runtime metadata
//! structure, so [`crate::build_info::print`] keeps the same tab-separated `key<TAB>value` grammar
//! and the same `path`/`mod`/`build` keys, translates the toolchain line to `rustc`, and names the
//! Rust-specific settings with a leading `-` like Go's build settings. The Caddy settings name is
//! spelled out (`-caddy-baseline`) so scripts can find it unambiguously.

use caddy_rs_core::{CADDY_COMPAT_BASELINE, VERSION};

/// Full `rustc --version` string emitted by `build.rs`.
pub(crate) const RUSTC_VERSION: &str = env!("CADDY_RS_BUILD_RUSTC");

/// Cargo's target triple for this build (for example `x86_64-unknown-linux-gnu`).
pub(crate) const TARGET_TRIPLE: &str = env!("CADDY_RS_BUILD_TARGET");

/// Cargo profile bucket (`debug` or `release`).
pub(crate) const BUILD_PROFILE: &str = env!("CADDY_RS_BUILD_PROFILE");

/// Cargo features enabled for this binary, in declaration order.
pub(crate) fn enabled_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "http3") {
        features.push("http3");
    }
    if cfg!(feature = "compression") {
        features.push("compression");
    }
    if cfg!(feature = "templates") {
        features.push("templates");
    }
    if cfg!(feature = "minimal") {
        features.push("minimal");
    }
    features
}

/// Format the enabled feature set for a single `build` line.
fn feature_list() -> String {
    let features = enabled_features();
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

/// Print Caddy's build-info shape with Rust values.
pub(crate) fn print(module_count: usize) {
    println!("rustc\t{RUSTC_VERSION}");
    println!("path\tcaddy-rs");
    // Go prints `mod<TAB>path<TAB>version<TAB>sum`; a local crate has no checksum, so the third
    // tab is left empty just as Go leaves it for module versions without a sum.
    println!("mod\tcaddy-rs\t{VERSION}\t");
    println!("build\t-profile={BUILD_PROFILE}");
    println!("build\t-target={TARGET_TRIPLE}");
    println!("build\t-features={}", feature_list());
    println!("build\t-modules={module_count}");
    println!("build\t-caddy-baseline={CADDY_COMPAT_BASELINE}");
}
