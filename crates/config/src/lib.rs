//! Caddyfile support: lexer, parser, and adapter to Caddy JSON.
//!
//! The adapter is the compatibility boundary for the user-facing configuration file. See the
//! program repository's `docs/compatibility/CADDYFILE.md` for the supported subset and every
//! intentional divergence.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod lexer;
pub mod parser;

pub use adapter::{adapt, CaddyfileAdapter};
pub use parser::{
    expand_env_vars, expand_env_vars_with, parse, Caddyfile, Directive, EnvExpansion,
    GlobalOptions, SiteAddress, SiteBlock,
};
