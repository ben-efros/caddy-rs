//! Caddyfile support: lexer, parser, and adapter to Caddy JSON.
//!
//! The adapter is the compatibility boundary for the user-facing configuration file. See the
//! `docs/compatibility/CADDYFILE.md` for the supported subset and every
//! intentional divergence.

// `deny` rather than `forbid`, so one narrowly-scoped module (`uid`) can allow the single
// `libc::geteuid` call the safe-mode import ownership rule needs; every other module stays
// unsafe-free. This mirrors `caddy-rs-server`'s `activation` module policy.
#![deny(unsafe_code)]

pub mod adapter;
mod glob;
pub mod layer4;
pub mod lexer;
pub mod parser;
#[cfg(unix)]
mod uid;

pub use adapter::{
    adapt, adapt_with_options, adapt_with_source, AdaptMode, AdaptOptions, CaddyfileAdapter,
};
#[cfg(unix)]
pub use parser::check_import_ownership;
pub use parser::{
    expand_env_vars, expand_env_vars_with, parse, parse_with_source, parse_with_source_and_policy,
    Caddyfile, Directive, EnvExpansion, GlobalOptions, ImportPolicy, NamedRoute,
    PkiCertificateAuthority, PkiKeyPairConfig, PkiOptions, SiteAddress, SiteBlock,
};
