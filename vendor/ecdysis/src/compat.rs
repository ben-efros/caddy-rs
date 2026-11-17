//! T-OPS-106 API-compat shim.
//!
//! This is the ONLY file added to upstream ecdysis 1.1.1 source; every other change in
//! `src/` is a one-line call-site substitution. The purpose is to keep ecdysis buildable
//! against the dependency versions caddy-rs requires for its audit gate:
//!
//!   * `nix` 0.26 -> 0.31.3: `fcntl()` now takes `Fd: AsFd` instead of `RawFd`.
//!   * `bincode` 1.3.3 -> `serde-wincode` 0.1.2 + `wincode` 0.6.3 (T-OPS-106c): bincode is
//!     BANNED from this repository -- RUSTSEC-2025-0141 has `patched = []`, so no bincode
//!     version can ever satisfy the audit gate. `serde_wincode::SerdeCompat` drives serde's
//!     own `Serialize`/`Deserialize` impls through wincode's arena-free `SchemaWrite`/
//!     `SchemaRead`, which defaults to bincode 1.x's wire rules.
//!
//! NO behaviour is changed here. The wire format is bincode 1.x's exactly: wincode's default
//! configuration is LittleEndian + Fixint + u64 (BincodeLen) length prefixes + u32 variant
//! tags + NoLimit, which is precisely the bincode 1.3.3 default. That equality is MEASURED,
//! not assumed, by `tests/golden_wire.rs`, which compares against a fixture produced by real
//! bincode 1.3.3 (118 bytes).
//!
//! Delete this module when upstream ecdysis ships nix >= 0.31 and a bincode-compatible
//! codec that is not bincode.

use std::{
    io::{Read, Write},
    os::fd::{BorrowedFd, RawFd},
};

/// The bincode 1.x wire configuration, spelled out for wincode.
///
/// `wincode::config::Configuration`'s defaults are, per wincode 0.6.3
/// (`config/mod.rs:45`): `BincodeLen` length prefix (u64 little-endian), `LittleEndian`
/// byte order, `FixInt` integer encoding, `u32` enum tags. That is exactly the bincode 1.3.3
/// default (`LittleEndian` + `Fixint` + `NoLimit`), so no non-default knobs are needed.
pub type WireConfig = wincode::config::Configuration;

/// The wincode successor of `bincode::Error`.
///
/// bincode 1.x had a single boxed error type. wincode splits encoding and decoding failures
/// into `WriteError` and `ReadError` (`serde-wincode` maps its own `ser::Error`/`de::Error`
/// into them via `From`); both are `std::error::Error`, so this small enum restores the single
/// error type the ecdysis error enums (`UpgradeError`, `InheritError`) are declared with. It
/// exists only so those enums need no change.
#[derive(Debug)]
pub enum Error {
    Encode(wincode::WriteError),
    Decode(wincode::ReadError),
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

impl From<wincode::WriteError> for Error {
    fn from(e: wincode::WriteError) -> Self {
        Error::Encode(e)
    }
}

impl From<wincode::ReadError> for Error {
    fn from(e: wincode::ReadError) -> Self {
        Error::Decode(e)
    }
}

/// 1.x `bincode::serialize_into(writer, value)`.
///
/// `serde_wincode::SerdeCompat<T>` is `SchemaWrite` for every `T: serde::Serialize`, so the
/// serde-derived impls of `ListenerInfo` are the ones on the wire -- byte-for-byte what
/// bincode 1.x wrote. `wincode::Serializer::new` then writes straight into the caller's
/// `std::io::Write` sink (the upgrade pipe), with no intermediate copy.
#[inline]
pub fn serialize_into<W: Write, T: serde::Serialize>(writer: W, value: &T) -> Result<(), Error> {
    let adapter = wincode::io::std_write::WriteAdapter::new(writer);
    let serializer = serde_wincode::Serializer::<_, WireConfig>::new(adapter);
    value
        .serialize(serializer)
        .map_err(|e| Error::Encode(wincode::WriteError::from(e)))?;
    Ok(())
}

/// 1.x `bincode::deserialize_from(reader)`.
///
/// The reader is wrapped in `wincode::io::ReadAdapter` so any `std::io::Read` (the inherited
/// upgrade pipe) can back the deserializer.
#[inline]
pub fn deserialize_from<R: Read, T: serde::de::DeserializeOwned>(reader: R) -> Result<T, Error> {
    let adapter = wincode::io::std_read::ReadAdapter::new(reader);
    let deserializer = serde_wincode::Deserializer::<_, WireConfig>::new(adapter);
    T::deserialize(deserializer).map_err(|e| Error::Decode(wincode::ReadError::from(e)))
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
