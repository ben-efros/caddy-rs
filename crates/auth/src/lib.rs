//! Static FIDO2/WebAuthn passkey registry for caddy-rs (T-AUTH-009 / ADR-034 §4.1).
//!
//! Deliberately stateless: public COSE keys are declared in configuration
//! (`apps.auth.passkeys`) or in a flat `authorized_passkeys` file, loaded once at configuration
//! load time, and never written back. There is no registration database.
//!
//! * [`cose`] parses COSE_Key CBOR and SPKI PEM public keys (ES256 and EdDSA).
//! * [`key_registry`] turns those keys plus metadata (`user`, `name`, `tags`, `transports`) into
//!   an immutable [`key_registry::KeyRegistry`].
//!
//! Every rejection carries a location (JSON path or `file:line`) so an operator can act on it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cose;
pub mod key_registry;

pub use cose::{CosePublicKey, Curve, KeyAlgorithm, KeyKind};
pub use key_registry::{KeyRegistry, PasskeyEntry, RegistryError};
