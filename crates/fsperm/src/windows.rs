//! Windows implementation: protected DACLs built from SDDL.
//!
//! See the crate docs for the model. Every `unsafe` block states the invariant it relies on.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFinalPathNameByHandleW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::Exposure;

/// `GENERIC_READ | GENERIC_WRITE` (declared here to avoid enabling another windows-sys feature).
const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;

/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// Access-mask bits that let a principal read file data or list a directory.
const READ_MASK: u32 = 0x0000_0001 // FILE_READ_DATA / FILE_LIST_DIRECTORY
    | 0x0000_0008 // FILE_READ_EA
    | 0x8000_0000 // GENERIC_READ
    | 0x1000_0000; // GENERIC_ALL

/// Access-mask bits that let a principal modify, replace or delete the object, or change who may.
/// On a directory these are the bits that let it delete or rename entries or alter permissions.
const WRITE_MASK: u32 = 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x4000_0000 // GENERIC_WRITE
    | 0x1000_0000; // GENERIC_ALL

/// Bits that write file data (`FILE_WRITE_DATA`, `FILE_APPEND_DATA`). On a file they modify it; on a
/// directory they are `FILE_ADD_FILE` / `FILE_ADD_SUBDIRECTORY`, i.e. creating entries.
const DATA_WRITE_MASK: u32 = 0x0000_0002 | 0x0000_0004;

/// `INHERIT_ONLY_ACE`: the entry applies to children only, never to the object it is attached to
/// (`C:\` carries several such entries for `Authenticated Users`).
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Principals that are not "others": SYSTEM, Administrators, CREATOR OWNER, OWNER RIGHTS and
/// TrustedInstaller. The current user's own SID is added at run time.
const TRUSTED_SIDS: &[&str] = &[
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-3-0",
    "S-1-3-4",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// UTF-16, NUL-terminated copy of `value` for a wide Win32 call.
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// A security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW` and
/// released with `LocalFree`.
struct OwnedDescriptor(*mut core::ffi::c_void);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Win32 call documented to require `LocalFree`, it is owned
        // exclusively by this value, and it is freed exactly once here.
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// String form of the SID of the user this process runs as (for example `S-1-5-21-…-1001`).
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` is a valid out-pointer and the process pseudo-handle needs no closing.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let result = (|| {
        let mut length = 0u32;
        // SAFETY: the first call only reports the required buffer size; a null buffer with length
        // zero is the documented way to ask.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length) };
        if length == 0 {
            return Err(last_error());
        }
        // `u64` elements give the 8-byte alignment `TOKEN_USER` requires.
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        // SAFETY: `buffer` is at least `length` bytes and suitably aligned; `length` is in/out.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(last_error());
        }
        // SAFETY: the call above filled `buffer` with a `TOKEN_USER` whose SID pointer targets
        // memory inside `buffer`, which outlives this use.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_to_string(sid)
    })();
    // SAFETY: `token` is a handle this function opened and has not closed.
    unsafe { CloseHandle(token) };
    result
}

/// Convert a binary SID to its `S-1-…` string form.
fn sid_to_string(sid: *mut core::ffi::c_void) -> io::Result<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: `sid` points at a valid SID for the duration of the call and `text` is a valid
    // out-pointer; on success the returned string is released with `LocalFree` below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(last_error());
    }
    // SAFETY: on success `text` is a NUL-terminated UTF-16 string allocated by the call.
    let string = unsafe {
        let mut length = 0usize;
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    };
    // SAFETY: `text` was allocated by `ConvertSidToStringSidW`, which requires `LocalFree`.
    unsafe { LocalFree(text.cast()) };
    Ok(string)
}

/// SDDL for "current user, SYSTEM and Administrators only", protected from inheritance.
///
/// Directories mark the grant inheritable (`OICI`) so new children are private from their first
/// byte; files carry a plain grant.
fn private_sddl(directory: bool) -> io::Result<String> {
    let user = current_user_sid()?;
    let flags = if directory { "OICI" } else { "" };
    Ok(format!(
        "D:P(A;{flags};FA;;;{user})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
    ))
}

fn descriptor_from_sddl(sddl: &str) -> io::Result<OwnedDescriptor> {
    let wide_sddl = wide(OsStr::new(sddl));
    let mut descriptor: *mut core::ffi::c_void = null_mut();
    // SAFETY: `wide_sddl` is NUL-terminated and outlives the call; `descriptor` is a valid
    // out-pointer; the allocation is owned by the returned `OwnedDescriptor`.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(OwnedDescriptor(descriptor))
}

pub(crate) fn create_dir_all_private(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    // Create missing ancestors first, outermost first, each private.
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        if candidate.as_os_str().is_empty() || candidate.is_dir() {
            break;
        }
        missing.push(candidate.to_path_buf());
        cursor = candidate.parent();
    }
    let descriptor = descriptor_from_sddl(&private_sddl(true)?)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: FALSE,
    };
    for directory in missing.iter().rev() {
        let wide_path = wide(directory.as_os_str());
        // SAFETY: `wide_path` is NUL-terminated and `attributes` points at a live descriptor that
        // outlives the call.
        if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
            let error = last_error();
            // A concurrent creator winning the race is fine.
            if error.kind() != io::ErrorKind::AlreadyExists || !directory.is_dir() {
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(crate) fn create_new_file_private(path: &Path) -> io::Result<File> {
    let descriptor = descriptor_from_sddl(&private_sddl(false)?)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: FALSE,
    };
    let wide_path = wide(path.as_os_str());
    // SAFETY: `wide_path` is NUL-terminated; `attributes` points at a live descriptor; the null
    // template handle is allowed. `CREATE_NEW` makes the call fail instead of opening an
    // existing file, so the DACL is always the one supplied here.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: `handle` is a valid, owned file handle that nothing else will close.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

pub(crate) fn restrict(path: &Path, directory: bool) -> io::Result<()> {
    let descriptor = descriptor_from_sddl(&private_sddl(directory)?)?;
    let mut present = 0i32;
    let mut defaulted = 0i32;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `descriptor.0` is a valid self-relative descriptor; the out-pointers are valid. The
    // returned ACL points *into* the descriptor, which lives until the end of this function.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(last_error());
    }
    let mut wide_path = wide(path.as_os_str());
    // SAFETY: `wide_path` is NUL-terminated (the API wants a mutable pointer but does not write
    // through it); `dacl` is valid while `descriptor` lives. PROTECTED stops inheritance from the
    // parent, which is the point.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

pub(crate) fn owned_by_current_user(path: &Path) -> io::Result<bool> {
    let user = current_user_sid()?;
    let wide_path = wide(path.as_os_str());
    let mut owner: *mut core::ffi::c_void = null_mut();
    let mut descriptor: *mut core::ffi::c_void = null_mut();
    // SAFETY: `wide_path` is NUL-terminated; the out-pointers are valid; on success `descriptor` is
    // a `LocalFree`-able allocation (released by the guard) and `owner` points into it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _guard = OwnedDescriptor(descriptor);
    if owner.is_null() {
        return Ok(false);
    }
    let owner_text = sid_to_string(owner)?;
    Ok(owner_text == user || owner_text == "S-1-5-18" || owner_text == "S-1-5-32-544")
}

pub(crate) fn exposure(path: &Path) -> io::Result<Exposure> {
    let user = current_user_sid()?;
    let wide_path = wide(path.as_os_str());
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: *mut core::ffi::c_void = null_mut();
    // SAFETY: `wide_path` is NUL-terminated; the out-pointers are valid; on success `descriptor`
    // is a `LocalFree`-able allocation that the guard below releases and `dacl` points into it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _guard = OwnedDescriptor(descriptor);
    if dacl.is_null() {
        // A NULL DACL grants everyone full access.
        return Ok(Exposure {
            readable_by_others: true,
            writable_by_others: true,
            creatable_by_others: true,
        });
    }
    let is_directory = path.is_dir();
    let mut exposure = Exposure::default();
    // SAFETY: `dacl` is a valid ACL (checked non-null) kept alive by `_guard`.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace: *mut core::ffi::c_void = null_mut();
        // SAFETY: `index < AceCount`, so `GetAce` returns a pointer to a valid ACE inside the ACL.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(last_error());
        }
        // SAFETY: every ACE starts with an `ACE_HEADER`.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue; // deny and audit entries do not grant access
        }
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue; // applies to children only, not to this object
        }
        // SAFETY: the type check above established this is an `ACCESS_ALLOWED_ACE`; its SID starts
        // at `SidStart`, which is the SID's first DWORD, so its address is the SID pointer.
        let (mask, sid) = unsafe {
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            (
                allowed.Mask,
                std::ptr::addr_of!(allowed.SidStart).cast_mut().cast(),
            )
        };
        let sid_text = sid_to_string(sid)?;
        if sid_text == user || TRUSTED_SIDS.contains(&sid_text.as_str()) {
            continue;
        }
        exposure.readable_by_others |= mask & READ_MASK != 0;
        exposure.writable_by_others |= mask & WRITE_MASK != 0;
        if mask & DATA_WRITE_MASK != 0 {
            if is_directory {
                exposure.creatable_by_others = true;
            } else {
                exposure.writable_by_others = true;
            }
        }
    }
    Ok(exposure)
}

/// Real path of an open file. See [`crate::final_path`].
pub(crate) fn final_path(file: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    let handle = file.as_raw_handle() as HANDLE;
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is a valid open file handle for the duration of the call and `buffer`
        // is writable for `buffer.len()` UTF-16 units. Flags 0 request the normalised DOS path.
        let length = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
        if length == 0 {
            return Err(last_error());
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
        }
        // The buffer was too small; `length` is the required size including the terminator.
        buffer = vec![0u16; length as usize + 1];
    }
}

/// Create exactly one directory with a protected owner-only DACL, failing if it exists. See
/// [`crate::create_dir_private`].
pub(crate) fn create_dir_private(path: &Path) -> io::Result<()> {
    let descriptor = descriptor_from_sddl(&private_sddl(true)?)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: FALSE,
    };
    let wide_path = wide(path.as_os_str());
    // SAFETY: `wide_path` is NUL-terminated and `attributes` points at a live descriptor that
    // outlives the call. `CreateDirectoryW` fails with ERROR_ALREADY_EXISTS for an existing path.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Open a regular file for reading. See [`crate::open_regular_file`].
pub(crate) fn open_regular_file(path: &Path) -> io::Result<File> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Real path of an open file. See [`crate::verified_real_path`]. Windows has no fallback: when the
/// handle's path cannot be read (some network redirectors), the caller keeps its path-based check.
pub(crate) fn verified_real_path(file: &File, _path: &Path) -> io::Result<PathBuf> {
    final_path(file)
}
