//! `CAP_NET_BIND_SERVICE` primitives (ADR-0046).
//!
//! Caddy v2.11.9 does not keep `CAP_NET_BIND_SERVICE` effective for its whole lifetime. It binds
//! first, and only if that fails with `EACCES` for a privileged TCP/UDP port does it raise the
//! capability — and only when the capability is *permitted but not effective* — bind again, then
//! lower it. That lets the binary be granted the capability with `setcap cap_net_bind_service=+p`
//! instead of `=+ep`: with the effective bit set the kernel refuses to execute the binary at all
//! when the capability cannot be granted (containers run with `--cap-drop ALL`, systemd units with
//! an empty `CapabilityBoundingSet`), even if it never binds a privileged port. See "Safety
//! checking for capability-dumb binaries" in `capabilities(7)`.
//!
//! This module supplies the low-level primitives that decision needs: the two UAPI structs, the
//! ABI version constant, the capability bit, the permitted/effective predicate, and the
//! raise/lower calls. It deliberately does **not** implement the bind-retry orchestration.
//!
//! # Delivery status
//!
//! **Primitives only.** Nothing in the server calls these yet: the bind-retry orchestration
//! (bind, and on `EACCES` for a privileged TCP/UDP port raise on a locked OS thread, bind again,
//! lower) is a separate task. Until that lands this module is API-only, which is why it carries a
//! scoped `dead_code` allowance rather than a caller. Do not read this module's presence as
//! `CAP_NET_BIND_SERVICE` parity being delivered — parity arrives when the orchestration does.
//!
//! # Why the structs are defined here
//!
//! `libc` 0.2.191 exposes `SYS_capget` and `SYS_capset` (verified: both present), but no
//! capability structs and no capability constants (verified: zero occurrences of
//! `__user_cap_header_struct`, `__user_cap_data_struct`, `LINUX_CAPABILITY_VERSION_3` and
//! `CAP_NET_BIND_SERVICE` anywhere in its source). They are therefore defined here from the Linux
//! UAPI headers, which are the normative source:
//!
//! | Item | UAPI provenance |
//! |---|---|
//! | `__user_cap_header_struct` | `include/uapi/linux/capability.h` — `{ __u32 version; int pid; }` |
//! | `__user_cap_data_struct` | `include/uapi/linux/capability.h` — `{ __u32 effective; __u32 permitted; __u32 inheritable; }` |
//! | `LINUX_CAPABILITY_VERSION_3` | `include/uapi/linux/capability.h` — `0x20080522` |
//! | `CAP_NET_BIND_SERVICE` | `include/uapi/linux/capability.h` — `10` |
//!
//! `capget(2)`/`capset(2)` take a **2-element** `__user_cap_data_struct` array for version 3,
//! covering capabilities 0..=63 across two 32-bit words; that is why [`CapData`] is `[_; 2]` and
//! matches the oracle's `[2]unix.CapUserData`.
//!
//! # Non-Linux
//!
//! Everything capability-related is `cfg(target_os = "linux")`. On other targets [`should_raise`]
//! and [`set_effective`] do not exist, mirroring the oracle's `bindcap_other.go` stub: callers keep
//! the current path and make no capability syscall.

// Primitives for the bind-retry orchestration ADR-0046 specifies, which is a separate task. Until
// it lands there is no production caller, so `dead_code` fires on every item. Allowing it here is a
// deliberate, temporary statement that this module is API-only for now — it is NOT a claim that the
// feature is delivered. Remove this allowance when the orchestration adds the caller.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
mod imp {
    // Syscalls are unavoidably unsafe; this is the narrowest possible escape from the crate-level
    // `#![deny(unsafe_code)]`, following the precedent of `activation.rs` and `udpgrm.rs`.
    #![allow(unsafe_code)]

    /// ABI version 3 of the capability syscall interface (`include/uapi/linux/capability.h`).
    ///
    /// The value is `_LINUX_CAPABILITY_VERSION_3`, i.e. `0x20080522`. Version 3 is the one that
    /// addresses 64 capabilities through a two-element data array.
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    /// `CAP_NET_BIND_SERVICE` (`include/uapi/linux/capability.h`, value 10).
    pub const CAP_NET_BIND_SERVICE: u32 = 10;

    /// `CAP_NET_BIND_SERVICE` as a mask suitable for testing/updating a capability word.
    pub const CAP_NET_BIND_SERVICE_MASK: u32 = 1 << CAP_NET_BIND_SERVICE;

    /// `struct __user_cap_header_struct` (`include/uapi/linux/capability.h`).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CapHeader {
        /// Capability ABI version; [`LINUX_CAPABILITY_VERSION_3`] for this module.
        pub version: u32,
        /// Target thread id, or `0` for the calling thread.
        pub pid: i32,
    }

    /// `struct __user_cap_data_struct` (`include/uapi/linux/capability.h`).
    ///
    /// One instance covers 32 capabilities; version 3 requires two of them.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CapData {
        pub effective: u32,
        pub permitted: u32,
        pub inheritable: u32,
    }

    /// The two-word capability data array `capget(2)`/`capset(2)` expect for version 3.
    pub type CapDataArray = [CapData; 2];

    /// Errors from the capability syscalls.
    #[derive(Debug)]
    pub enum CapError {
        /// `capget(2)`/`capset(2)` returned an error; carries the OS error.
        Syscall(std::io::Error),
    }

    impl std::fmt::Display for CapError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Syscall(error) => write!(f, "capability syscall failed: {error}"),
            }
        }
    }

    impl std::error::Error for CapError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Syscall(error) => Some(error),
            }
        }
    }

    /// Read the capability sets of the calling thread.
    ///
    /// The oracle reads the header back and reuses it for the subsequent `capset`; the version
    /// field is therefore returned alongside the data.
    pub fn get() -> Result<(CapHeader, CapDataArray), CapError> {
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data: CapDataArray = Default::default();
        // SAFETY: `header` and `data` are both `repr(C)` structs matching the UAPI layout
        // (`__user_cap_header_struct` is 8 bytes, `__user_cap_data_struct` is 12), they are live
        // for the duration of the call, and `data` has exactly the two elements version 3
        // requires. The kernel writes at most those two elements.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(CapError::Syscall(std::io::Error::last_os_error()));
        }
        Ok((header, data))
    }

    /// Write the effective set of the calling thread, leaving permitted and inheritable unchanged.
    ///
    /// The caller must have obtained `data` from [`get`], so the words being written back are the
    /// thread's own sets rather than a fabricated value.
    pub fn set(header: &CapHeader, data: &CapDataArray) -> Result<(), CapError> {
        let mut header = *header;
        let mut data = *data;
        // SAFETY: both pointers refer to live, correctly-typed `repr(C)` values that outlive the
        // call, and the layout matches what `capset(2)` expects for the given version.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(CapError::Syscall(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Whether `CAP_NET_BIND_SERVICE` is permitted but not effective for the calling thread.
    ///
    /// This is the oracle's predicate (`shouldRaiseBindCapability`): raise the capability only when
    /// it is *permitted* (so raising cannot fail for lack of permission) and not already
    /// *effective* (so there is nothing to do otherwise).
    pub fn should_raise() -> Result<bool, CapError> {
        let (_, data) = get()?;
        Ok(should_raise_from(&data))
    }

    /// The predicate over an already-read capability array.
    ///
    /// Split out from [`should_raise`] so the four permitted/effective combinations can be tested
    /// without a capability syscall: a process cannot grant itself capabilities it does not have,
    /// so the interesting cases cannot be arranged by running the test binary differently.
    pub fn should_raise_from(data: &CapDataArray) -> bool {
        data[0].permitted & CAP_NET_BIND_SERVICE_MASK != 0
            && data[0].effective & CAP_NET_BIND_SERVICE_MASK == 0
    }

    /// Add or remove `CAP_NET_BIND_SERVICE` in the calling thread's effective set.
    ///
    /// To add it the capability must already be permitted. Capabilities are per-thread, so this
    /// affects the calling thread only — the oracle calls it on a locked OS thread.
    pub fn set_effective(effective: bool) -> Result<(), CapError> {
        let (header, mut data) = get()?;
        if effective {
            data[0].effective |= CAP_NET_BIND_SERVICE_MASK;
        } else {
            data[0].effective &= !CAP_NET_BIND_SERVICE_MASK;
        }
        set(&header, &data)
    }
}

#[cfg(target_os = "linux")]
pub use imp::{
    CapData, CapDataArray, CapError, CapHeader, CAP_NET_BIND_SERVICE, CAP_NET_BIND_SERVICE_MASK,
    LINUX_CAPABILITY_VERSION_3,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn abi_structures_match_the_uapi_layout() {
        use std::mem::{align_of, size_of};

        // `__user_cap_header_struct` is `{ __u32 version; int pid; }`.
        assert_eq!(size_of::<CapHeader>(), 8);
        assert_eq!(align_of::<CapHeader>(), 4);

        // `__user_cap_data_struct` is three `__u32`s.
        assert_eq!(size_of::<CapData>(), 12);
        assert_eq!(align_of::<CapData>(), 4);

        // Version 3 requires a two-element array, covering capabilities 0..=63.
        assert_eq!(size_of::<CapDataArray>(), 24);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn version_and_capability_constants_are_the_uapi_values() {
        // `_LINUX_CAPABILITY_VERSION_3` is 0x20080522.
        assert_eq!(LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        // `CAP_NET_BIND_SERVICE` is 10, so its mask is bit 10.
        assert_eq!(CAP_NET_BIND_SERVICE, 10);
        assert_eq!(CAP_NET_BIND_SERVICE_MASK, 1 << 10);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn should_raise_covers_all_four_permitted_effective_combinations() {
        // The oracle raises only when permitted AND not effective. Each of the four
        // permitted/effective combinations is asserted explicitly, so a change to either
        // conjunct fails here.
        fn data(permitted: bool, effective: bool) -> CapDataArray {
            let mut data = [CapData::default(); 2];
            if permitted {
                data[0].permitted = CAP_NET_BIND_SERVICE_MASK;
            }
            if effective {
                data[0].effective = CAP_NET_BIND_SERVICE_MASK;
            }
            data
        }

        // permitted + not effective -> raise (the only case that raises)
        assert!(imp::should_raise_from(&data(true, false)));
        // permitted + effective -> nothing to do
        assert!(!imp::should_raise_from(&data(true, true)));
        // not permitted + not effective -> raising would fail, do not try
        assert!(!imp::should_raise_from(&data(false, false)));
        // not permitted + effective -> cannot happen for a real thread, but must not raise
        assert!(!imp::should_raise_from(&data(false, true)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn predicate_ignores_other_capabilities_and_the_second_word() {
        // A thread with many capabilities but not CAP_NET_BIND_SERVICE must not raise: the
        // predicate tests the specific bit, not "any capability set".
        let mut data = [CapData::default(); 2];
        data[0].permitted = 0xffff_ffff & !CAP_NET_BIND_SERVICE_MASK;
        data[1].permitted = 0xffff_ffff;
        assert!(!imp::should_raise_from(&data));

        // And a capability in the SECOND word must not be mistaken for CAP_NET_BIND_SERVICE,
        // which lives in the first word.
        let mut second_word_only = [CapData::default(); 2];
        second_word_only[1].permitted = CAP_NET_BIND_SERVICE_MASK;
        assert!(!imp::should_raise_from(&second_word_only));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_reads_the_calling_threads_capabilities() {
        // Reading must succeed in any ordinary process, and the header must be version 3.
        let (header, _data) = imp::get().expect("capget on the calling thread");
        assert_eq!(header.version, LINUX_CAPABILITY_VERSION_3);
        assert_eq!(header.pid, 0, "pid 0 means the calling thread");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_effective_is_a_round_trip_when_the_capability_is_absent() {
        // This test asserts only what is true regardless of the test runner's privileges: setting
        // the effective bit to the value it already has must succeed and must not change the
        // observed predicate. It never grants a capability the process does not have, because
        // `set_effective(false)` on an absent bit is a no-op and `set_effective(true)` would
        // fail with EPERM if the capability were not permitted.
        let (_, before) = imp::get().expect("capget");
        let already_effective = before[0].effective & CAP_NET_BIND_SERVICE_MASK != 0;

        // Lowering an absent bit, or re-asserting a present one, must be accepted by the kernel.
        imp::set_effective(already_effective).expect("capset re-asserting the current state");

        let (_, after) = imp::get().expect("capget after capset");
        assert_eq!(
            after[0].effective & CAP_NET_BIND_SERVICE_MASK != 0,
            already_effective,
            "re-asserting the current effective bit must not change it"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raising_an_unpermitted_capability_is_an_error_not_a_silent_no_op() {
        // If the test runner does not have CAP_NET_BIND_SERVICE permitted, asking to raise it
        // must fail with EPERM rather than appearing to succeed. If it does have it, this is a
        // no-op and the test is vacuous but harmless. Either way the code must not claim success
        // while the kernel refused.
        let (_, data) = imp::get().expect("capget");
        if imp::should_raise_from(&data) {
            // Permitted but not effective: raising is allowed and must work.
            imp::set_effective(true).expect("raising a permitted capability");
            let (_, raised) = imp::get().expect("capget");
            assert!(raised[0].effective & CAP_NET_BIND_SERVICE_MASK != 0);
            imp::set_effective(false).expect("lowering it again");
            let (_, lowered) = imp::get().expect("capget");
            assert!(lowered[0].effective & CAP_NET_BIND_SERVICE_MASK == 0);
        } else if data[0].permitted & CAP_NET_BIND_SERVICE_MASK == 0 {
            // Not permitted: the kernel must refuse.
            let error =
                imp::set_effective(true).expect_err("raising an unpermitted capability must fail");
            let CapError::Syscall(io) = error;
            assert_eq!(io.raw_os_error(), Some(libc::EPERM));
            // And the failed attempt must have left the effective set untouched.
            let (_, unchanged) = imp::get().expect("capget");
            assert!(unchanged[0].effective & CAP_NET_BIND_SERVICE_MASK == 0);
        }
    }
}
