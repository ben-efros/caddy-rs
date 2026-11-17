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
        /// `CAP_NET_BIND_SERVICE` was found in at least one set when fdstore mode requires it
        /// absent (ADR-0047 §6).
        Present(BindCapabilityPresence),
    }

    impl std::fmt::Display for CapError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Syscall(error) => write!(f, "capability syscall failed: {error}"),
                Self::Present(presence) => write!(
                    f,
                    "CAP_NET_BIND_SERVICE must be absent in fdstore mode (ADR-0047) but is \
                     present: {}",
                    presence.describe()
                ),
            }
        }
    }

    impl std::error::Error for CapError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Syscall(error) => Some(error),
                Self::Present(_) => None,
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

    /// `PR_CAP_AMBIENT` (`include/uapi/linux/prctl.h`).
    pub const PR_CAP_AMBIENT: libc::c_int = 47;
    /// `PR_CAP_AMBIENT_IS_SET` (`include/uapi/linux/prctl.h`).
    pub const PR_CAP_AMBIENT_IS_SET: libc::c_int = 1;

    /// Whether `CAP_NET_BIND_SERVICE` is in the calling thread's **ambient** set.
    ///
    /// The ambient set is deliberately *not* in what `capget(2)` returns — that syscall reports
    /// effective, permitted and inheritable only — so it must be read with
    /// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0)`, which returns 1 when set, 0 when
    /// not, or -1 with `errno` set. ADR-0047 §6 requires the fdstore-mode assertion to cover the
    /// ambient set as well as permitted and effective, so reading only `capget` would silently
    /// under-report and let a binary with ambient `CAP_NET_BIND_SERVICE` pass the check.
    pub fn ambient_has_bind_service() -> Result<bool, CapError> {
        // SAFETY: `prctl` with `PR_CAP_AMBIENT_IS_SET` only reads thread state; all arguments are
        // plain integers and no pointers are passed.
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_IS_SET,
                CAP_NET_BIND_SERVICE as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(CapError::Syscall(std::io::Error::last_os_error())),
        }
    }

    /// The three capability sets ADR-0047 §6 requires fdstore mode to be free of.
    ///
    /// Note the deliberate contrast with ADR-0046: there `CAP_NET_BIND_SERVICE` is legitimately
    /// *permitted*, because the process raises it on demand. In fdstore mode the capability must be
    /// absent from all three sets, because the sockets are already bound and the process must never
    /// need the privilege. The two modes are mutually exclusive.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BindCapabilityPresence {
        pub permitted: bool,
        pub effective: bool,
        pub ambient: bool,
    }

    impl BindCapabilityPresence {
        /// Whether the capability is absent from every set, as fdstore mode requires.
        pub fn is_absent(&self) -> bool {
            !self.permitted && !self.effective && !self.ambient
        }

        /// A human-readable summary for the startup log line.
        pub fn describe(&self) -> String {
            format!(
                "permitted={} effective={} ambient={}",
                self.permitted, self.effective, self.ambient
            )
        }
    }

    /// Read `CAP_NET_BIND_SERVICE`'s presence across all three sets.
    pub fn bind_service_presence() -> Result<BindCapabilityPresence, CapError> {
        let (_, data) = get()?;
        Ok(BindCapabilityPresence {
            permitted: data[0].permitted & CAP_NET_BIND_SERVICE_MASK != 0,
            effective: data[0].effective & CAP_NET_BIND_SERVICE_MASK != 0,
            ambient: ambient_has_bind_service()?,
        })
    }

    /// Assert that fdstore mode is free of `CAP_NET_BIND_SERVICE` (ADR-0047 §6).
    ///
    /// Returns the observed presence either way so the caller can log it; the error case carries
    /// the offending set(s).
    pub fn assert_bind_service_absent() -> Result<BindCapabilityPresence, CapError> {
        let presence = bind_service_presence()?;
        if presence.is_absent() {
            Ok(presence)
        } else {
            Err(CapError::Present(presence))
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{
    assert_bind_service_absent, bind_service_presence, BindCapabilityPresence, CapData,
    CapDataArray, CapError, CapHeader, CAP_NET_BIND_SERVICE, CAP_NET_BIND_SERVICE_MASK,
    LINUX_CAPABILITY_VERSION_3,
};

#[cfg(test)]
#[allow(unsafe_code)] // one test calls prctl directly to construct the ambient-true case.
mod tests {
    use super::*;

    /// Whether `no_new_privs` is set for this process (`/proc/self/status: NoNewPrivs`).
    ///
    /// With it set the kernel refuses `PR_CAP_AMBIENT_RAISE` regardless of permissions, so tests
    /// that need to construct an ambient capability must detect it and say they skipped.
    #[cfg(target_os = "linux")]
    fn no_new_privs_is_set() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("NoNewPrivs:"))
                    .and_then(|line| line.split_whitespace().nth(1).map(str::to_string))
            })
            .is_some_and(|value| value == "1")
    }

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
    fn presence_covers_all_three_sets_including_ambient() {
        // ADR-0047 §6 needs permitted AND effective AND ambient. The ambient set is not in
        // capget's output, so a check that only read capget would under-report; this asserts the
        // struct distinguishes all three independently.
        let none = BindCapabilityPresence {
            permitted: false,
            effective: false,
            ambient: false,
        };
        assert!(none.is_absent());

        for presence in [
            BindCapabilityPresence {
                permitted: true,
                effective: false,
                ambient: false,
            },
            BindCapabilityPresence {
                permitted: false,
                effective: true,
                ambient: false,
            },
            // ambient alone must NOT count as absent: this is the case a capget-only check misses
            BindCapabilityPresence {
                permitted: false,
                effective: false,
                ambient: true,
            },
        ] {
            assert!(
                !presence.is_absent(),
                "{} must not be treated as absent",
                presence.describe()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ambient_read_sees_a_capability_that_is_actually_ambient() {
        // A stub that always returns false would pass a test written only for the absent case, so
        // this test RAISES the ambient bit for real and requires the read to observe it. Raising an
        // ambient capability requires it to be permitted and effective first, so the test does all
        // three and restores the original state afterwards.
        let (header, original) = imp::get().expect("capget");
        let mask = CAP_NET_BIND_SERVICE_MASK;
        if original[0].permitted & mask == 0 {
            // Without the capability this test cannot construct the case; say so rather than
            // silently passing as though it had verified something.
            eprintln!(
                "SKIPPED: CAP_NET_BIND_SERVICE is not permitted here, so the ambient-true branch \
                 cannot be constructed"
            );
            return;
        }
        // `no_new_privs` forbids raising an ambient capability outright, so in such a sandbox the
        // true branch is unreachable no matter how privileged the process is. Detect it up front
        // and report, instead of failing on an EPERM that says nothing about the implementation.
        if no_new_privs_is_set() {
            eprintln!(
                "SKIPPED: no_new_privs is set, so PR_CAP_AMBIENT_RAISE is forbidden by the kernel; \
                 the ambient-true branch cannot be constructed in this sandbox"
            );
            return;
        }

        // 1. Make it effective and permitted (required before raising it ambient).
        let mut raised = original;
        raised[0].effective |= mask;
        raised[0].permitted |= mask;
        imp::set(&header, &raised).expect("raise effective+permitted");
        // 2. Raise it ambient.
        // SAFETY: PR_CAP_AMBIENT_RAISE only affects the calling thread and takes plain integers.
        let rc = unsafe {
            libc::prctl(
                imp::PR_CAP_AMBIENT,
                // PR_CAP_AMBIENT_RAISE
                2,
                CAP_NET_BIND_SERVICE as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        assert_eq!(
            rc,
            0,
            "raising the ambient capability: {}",
            std::io::Error::last_os_error()
        );

        // 3. The read MUST now see it. This is what fails if the implementation is a stub.
        let observed = imp::ambient_has_bind_service().expect("ambient read");
        assert!(
            observed,
            "the ambient set contains CAP_NET_BIND_SERVICE but the read reported false"
        );
        let presence = imp::bind_service_presence().expect("presence");
        assert!(presence.ambient, "presence must report the ambient bit");
        assert!(
            !presence.is_absent(),
            "with the capability ambient, the fdstore assertion must not report absent"
        );

        // 4. Restore: lower the ambient bit and the effective bit.
        // SAFETY: PR_CAP_AMBIENT_LOWER only affects the calling thread.
        unsafe {
            libc::prctl(
                imp::PR_CAP_AMBIENT,
                // PR_CAP_AMBIENT_LOWER
                3,
                CAP_NET_BIND_SERVICE as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
        }
        imp::set(&header, &original).expect("restore the original capability sets");
        assert!(
            !imp::ambient_has_bind_service().expect("ambient read after lowering"),
            "the ambient bit must be gone after the test restores state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ambient_set_is_readable_and_reflects_reality() {
        // The ambient read must actually work (not error), and its answer must agree with the
        // kernel rather than being hard-coded false.
        let ambient = imp::ambient_has_bind_service().expect("prctl PR_CAP_AMBIENT_IS_SET");
        // A process with no permitted capability cannot have an ambient one, so ambient implies
        // permitted. Asserting the implication catches a stub that returns true unconditionally.
        if ambient {
            let (_, data) = imp::get().expect("capget");
            assert!(
                data[0].permitted & CAP_NET_BIND_SERVICE_MASK != 0,
                "an ambient CAP_NET_BIND_SERVICE implies it is permitted"
            );
        }
        let presence = imp::bind_service_presence().expect("presence");
        assert_eq!(presence.ambient, ambient);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fdstore_assertion_reports_the_observed_state_either_way() {
        // The assertion must be usable as a startup gate: on success it returns what it saw so the
        // caller can log it, and on failure the error names the offending sets. This test asserts
        // the contract without depending on the test runner's privileges.
        match imp::assert_bind_service_absent() {
            Ok(presence) => {
                assert!(presence.is_absent());
                assert!(presence.describe().contains("ambient="));
            }
            Err(CapError::Present(presence)) => {
                assert!(!presence.is_absent());
                let message = CapError::Present(presence).to_string();
                assert!(message.contains("CAP_NET_BIND_SERVICE"));
                assert!(message.contains("fdstore"));
            }
            Err(other) => panic!("unexpected error from the presence check: {other}"),
        }
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
            match error {
                CapError::Syscall(io) => assert_eq!(io.raw_os_error(), Some(libc::EPERM)),
                other => panic!("raising an unpermitted capability must fail with EPERM: {other}"),
            }
            // And the failed attempt must have left the effective set untouched.
            let (_, unchanged) = imp::get().expect("capget");
            assert!(unchanged[0].effective & CAP_NET_BIND_SERVICE_MASK == 0);
        }
    }
}
