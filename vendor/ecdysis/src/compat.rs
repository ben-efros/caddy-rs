//! T-OPS-106 API-compat shim.
//!
//! This is the ONLY file added to upstream ecdysis 1.1.1 source; every other change in
//! `src/` is a one-line call-site substitution. The purpose is to keep ecdysis buildable
//! against the dependency versions caddy-rs requires for its audit gate:
//!
//!   * `nix` 0.26 -> 0.31.3: `fcntl()` now takes `Fd: AsFd` instead of `RawFd`.
//!   * `bincode` 1.3.3 -> 2.0.1: `serialize_into` / `deserialize_from` / `bincode::Error`
//!     were removed in favour of the `Encode`/`Decode` traits and an explicit `Config`.
//!
//! NO behaviour is changed here. The wire format is bincode 1.x's exactly: the
//! `bincode::config::legacy()` configuration is LittleEndian + Fixint + NoLimit, which is
//! precisely the bincode 1.3.3 default. That equality is MEASURED, not assumed, by
//! `tests/golden_wire.rs`, which decodes a fixture produced by real bincode 1.3.3.
//!
//! Delete this module when upstream ecdysis ships nix >= 0.31 and bincode 2.x.

use std::{
    io::{Read, Write},
    os::fd::{BorrowedFd, RawFd},
};

use bincode::config;

/// The bincode 1.x wire configuration, spelled out for bincode 2.x.
///
/// `legacy()` is LittleEndian + Fixint + NoLimit (bincode-2.0.1/src/config.rs:62) and is
/// documented upstream as "the default config that was present in bincode 1.0".
#[inline]
pub fn wire_config() -> config::Configuration<config::LittleEndian, config::Fixint, config::NoLimit>
{
    config::legacy()
}

/// The bincode 2.x successor of `bincode::Error`.
///
/// bincode 1.x had a single boxed error type. bincode 2.x splits encoding and decoding
/// failures into `EncodeError` and `DecodeError`; both are `std::error::Error`, so this
/// small enum restores the single error type the ecdysis error enums (`UpgradeError`,
/// `InheritError`) are declared with. It exists only so those enums need no change.
#[derive(Debug)]
pub enum Error {
    Encode(bincode::error::EncodeError),
    Decode(bincode::error::DecodeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encode(e) => write!(f, "{}", e),
            Error::Decode(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<bincode::error::EncodeError> for Error {
    fn from(e: bincode::error::EncodeError) -> Self {
        Error::Encode(e)
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(e: bincode::error::DecodeError) -> Self {
        Error::Decode(e)
    }
}

/// 1.x `bincode::serialize_into(writer, value)` -> 2.x `encode_into_std_write`.
#[inline]
pub fn serialize_into<W: Write, T: serde::Serialize>(writer: W, value: &T) -> Result<(), Error> {
    let mut writer = writer;
    bincode::serde::encode_into_std_write(value, &mut writer, wire_config())?;
    Ok(())
}

/// 1.x `bincode::deserialize_from(reader)` -> 2.x `decode_from_std_read`.
#[inline]
pub fn deserialize_from<R: Read, T: serde::de::DeserializeOwned>(reader: R) -> Result<T, Error> {
    let mut reader = reader;
    Ok(bincode::serde::decode_from_std_read(
        &mut reader,
        wire_config(),
    )?)
}

/// nix 0.26 `fcntl(RawFd, _)` -> nix 0.31 `fcntl(impl AsFd, _)`.
///
/// The caller passes the same raw descriptor number it always did; borrowing it here is a
/// pure type-level adaptation and transfers no ownership (the `BorrowedFd` is dropped
/// immediately and never closed).
#[inline]
pub(crate) fn borrowed_fd(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: every call site passes a descriptor number that was already in use by ecdysis
    // under nix 0.26 (an inherited or duplicated socket/pipe descriptor owned elsewhere in
    // the process). The returned `BorrowedFd` is used only for the duration of one `fcntl`
    // call and is never used to close the descriptor, so it cannot introduce a double close.
    unsafe { BorrowedFd::borrow_raw(fd) }
}
