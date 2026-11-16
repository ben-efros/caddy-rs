//! Effective-uid lookup for the safe-mode import ownership rule.
//!
//! ## Unsafe code
//!
//! Reading the effective uid requires `libc::geteuid`, which is an `unsafe` foreign function; std
//! exposes no safe equivalent. The crate denies unsafe code (`#![deny(unsafe_code)]`) and only
//! this module allows it. The call takes no arguments, cannot fail, returns a plain integer, and
//! touches no memory or file descriptors, so there is no invariant to violate. This mirrors
//! `caddy-rs-server`'s `activation` module policy of one narrowly-scoped allowance.

#![allow(unsafe_code)]

/// The effective uid of the current process.
///
/// `geteuid` (not `getuid`) is the identity the kernel uses for permission checks, so it is the
/// one that decides whether an ownership-anchored import is trusted.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::geteuid() }
}
