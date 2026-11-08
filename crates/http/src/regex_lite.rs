//! Compatibility re-export of the shared `caddy-rs-core` regex wrapper.
//!
//! All regexes in the HTTP engine now use [`caddy_rs_core::regex`]; this module keeps the
//! historical `crate::regex_lite::Regex` path used by handlers and the proxy health check.

pub use caddy_rs_core::regex::{Captures, Regex, RegexError};
