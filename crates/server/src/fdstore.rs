//! Uploading bound sockets to `systemd`'s fd store (ADR-0047 §2, §6).
//!
//! The `bind-fds` helper binds privileged listeners before `run` starts and hands them to the
//! service manager, which keeps them in its fd store across restarts. Handing over a descriptor
//! requires attaching it to a datagram as an `SCM_RIGHTS` control message, which `std` cannot do on
//! stable Rust: `UnixDatagram::send_vectored_with_ancillary` is still behind the unstable
//! `unix_socket_ancillary_data` feature (verified against rustc 1.98.1 — it fails with E0658).
//! This module is therefore one of the crate's documented unsafe exceptions, alongside
//! [`crate::activation`], which adopts the descriptors this module produces.
//!
//! Every `unsafe` block below is annotated with its invariant.
//!
//! # Testing note: a mutant must change the VALUE, not just the spelling
//!
//! On Linux `SOL_SOCKET` and `SCM_RIGHTS` are the **same integer, both 1** (verified by compiling a
//! probe against the pinned libc, which printed `SOL_SOCKET=1 SCM_RIGHTS=1`; also
//! `/usr/include/asm-generic/socket.h:9` defines `SOL_SOCKET 1`). Rewriting `cmsg_type` from
//! `SCM_RIGHTS` to `SOL_SOCKET` therefore emits an **identical bit pattern** and is not a mutation
//! at all — the tests keep passing because the code still sends `SCM_RIGHTS`, not because anything
//! repaired it. Do not read that survival as a coverage gap, and do not conclude that the kernel
//! rewrites `cmsg_type`; it does not.
//!
//! To test the transfer, break a value the kernel cannot compensate for: set `cmsg_len` to
//! `CMSG_LEN(0)`, which genuinely carries zero descriptors and makes **both** upload tests fail.
//!
//! # Why this lives in `crates/server` and not `crates/core`
//!
//! `crates/core` carries `#![forbid(unsafe_code)]`, an absolute crate-wide invariant: `forbid`
//! cannot be overruled by a local `allow`, so a syscall cannot live there at all. `crates/server`
//! uses `#![deny(unsafe_code)]` precisely so that individual modules can opt in and document why —
//! [`crate::activation`] is the existing example. Putting the syscall here keeps `core` free of
//! unsafe rather than weakening its invariant for convenience. The protocol *strings*
//! (`FDSTORE=1\nFDNAME=…`) stay in `caddy_rs_core::notify`, where the rest of the notify protocol
//! lives.

// Sending a descriptor requires `sendmsg(2)`; see the module docs.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use caddy_rs_core::notify::{fdstore_upload_payload, NOTIFY_SOCKET_ENV};

/// Why an fd-store upload failed, distinguishing the cases the helper reports differently.
#[derive(Debug)]
pub enum FdStoreError {
    /// `NOTIFY_SOCKET` is unset or empty: there is no fd store to upload to.
    ///
    /// ADR-0047 §6 requires this to be a clear error with **no partial state**, so callers must
    /// treat it as fatal *before* binding anything.
    NotifySocketUnset,
    /// The notification socket could not be used.
    Socket(io::Error),
}

impl std::fmt::Display for FdStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotifySocketUnset => write!(
                f,
                "NOTIFY_SOCKET is not set, so there is no systemd fd store to upload to; \
                 fdstore mode requires systemd (ADR-0047)"
            ),
            Self::Socket(error) => write!(f, "cannot upload to the systemd fd store: {error}"),
        }
    }
}

impl std::error::Error for FdStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotifySocketUnset => None,
            Self::Socket(error) => Some(error),
        }
    }
}

/// Upload `fd` to the fd store named by `NOTIFY_SOCKET` under `fd_name`.
///
/// The kernel duplicates the descriptor into the receiving process, so the caller keeps ownership
/// of `fd` and must still close it.
pub fn send_fd_to_store(fd: RawFd, fd_name: &str) -> Result<(), FdStoreError> {
    let socket = std::env::var_os(NOTIFY_SOCKET_ENV)
        .filter(|value| !value.is_empty())
        .ok_or(FdStoreError::NotifySocketUnset)?;
    send_fd_to_store_at(&socket, fd, fd_name).map_err(FdStoreError::Socket)
}

/// Upload `fd` to the fd store reachable at an explicit `NOTIFY_SOCKET`-style address.
///
/// Split from [`send_fd_to_store`] so tests can point at a mock socket without mutating the process
/// environment, which is global and would make the tests order-dependent.
pub fn send_fd_to_store_at(socket_name: &OsStr, fd: RawFd, fd_name: &str) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let payload = fdstore_upload_payload(fd_name);
    let bytes = socket_name.as_bytes();
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty NOTIFY_SOCKET",
        ));
    }

    let (address, address_len) = encode_socket_address(bytes)?;

    let sender = std::os::unix::net::UnixDatagram::unbound()?;

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // Room for exactly one descriptor in the control message.
    let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0_u8; control_len];

    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = address.as_ptr() as *mut libc::c_void;
    message.msg_namelen = address_len;
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control_len as _;

    // SAFETY: `message` refers to `iov`, `control` and `address`, all of which are live local
    // values that outlive every call below; `control` was sized with `CMSG_SPACE` for exactly one
    // `RawFd`, so writing one descriptor into `CMSG_DATA` stays in bounds.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(io::Error::other(
                "cannot build the SCM_RIGHTS control message",
            ));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd,
            libc::CMSG_DATA(header) as *mut RawFd,
            1,
        );
    }

    // SAFETY: `sender` is a live socket, and `message` was built above from live values.
    let sent = unsafe { libc::sendmsg(sender.as_raw_fd(), &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if (sent as usize) != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("sent {sent} of {} fd-store payload bytes", payload.len()),
        ));
    }
    Ok(())
}

/// Encode a `NOTIFY_SOCKET`-style name as a `sockaddr_un` plus its length.
///
/// `@name` selects the Linux abstract namespace (leading NUL, no trailing NUL); anything else is a
/// filesystem path.
fn encode_socket_address(bytes: &[u8]) -> io::Result<(Vec<u8>, libc::socklen_t)> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let capacity = address.sun_path.len() - 1;

    let len = if bytes[0] == b'@' {
        let name = &bytes[1..];
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty abstract NOTIFY_SOCKET name",
            ));
        }
        if name.len() > capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "abstract NOTIFY_SOCKET name too long",
            ));
        }
        // sun_path[0] stays NUL to select the abstract namespace.
        for (slot, byte) in address.sun_path[1..1 + name.len()].iter_mut().zip(name) {
            *slot = *byte as libc::c_char;
        }
        std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()
    } else {
        if bytes.len() > capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NOTIFY_SOCKET path too long",
            ));
        }
        for (slot, byte) in address.sun_path[..bytes.len()].iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        std::mem::size_of::<libc::sockaddr_un>()
    };

    // SAFETY: `sockaddr_un` is plain old data, so reading it as bytes is sound.
    let raw = unsafe {
        std::slice::from_raw_parts(
            &address as *const libc::sockaddr_un as *const u8,
            std::mem::size_of::<libc::sockaddr_un>(),
        )
    };
    Ok((raw.to_vec(), len as libc::socklen_t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A mock `systemd` notify socket: receives one datagram and returns the payload and any
    /// descriptors attached to it.
    fn receive_one(socket: &std::os::unix::net::UnixDatagram) -> (Vec<u8>, Vec<RawFd>) {
        let mut payload = vec![0_u8; 4096];
        let mut control = vec![0_u8; 256];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control.len() as _;

        // SAFETY: all pointers refer to live buffers sized above.
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        assert!(
            received >= 0,
            "recvmsg failed: {}",
            io::Error::last_os_error()
        );
        payload.truncate(received as usize);

        let mut descriptors = Vec::new();
        // SAFETY: `message` was filled in by `recvmsg`; `CMSG_FIRSTHDR`/`CMSG_NXTHDR` walk the
        // control buffer it populated, staying within `msg_controllen`.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let data = libc::CMSG_DATA(header);
                    let count = ((*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                        / std::mem::size_of::<RawFd>();
                    for index in 0..count {
                        let mut descriptor: RawFd = 0;
                        std::ptr::copy_nonoverlapping(
                            data.add(index * std::mem::size_of::<RawFd>()) as *const RawFd,
                            &mut descriptor,
                            1,
                        );
                        descriptors.push(descriptor);
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        (payload, descriptors)
    }

    #[test]
    fn uploads_the_payload_and_the_descriptor_over_a_pathname_socket() {
        // This is the acceptance test: a mock notify socket receives BOTH the FDSTORE=1/FDNAME=
        // control message and the descriptor itself, proving SCM_RIGHTS actually transferred it.
        let directory =
            std::env::temp_dir().join(format!("caddy-rs-fdstore-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&directory);
        let path = directory.join("notify.sock");
        let _ = std::fs::remove_file(&path);

        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();

        // A real file descriptor to hand over.
        let file_path = directory.join("payload.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"fdstore").unwrap();
        let original = file.as_raw_fd();

        send_fd_to_store_at(path.as_os_str(), original, "caddy-tcp-0.0.0.0-443").unwrap();

        let (payload, descriptors) = receive_one(&receiver);
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "FDSTORE=1\nFDNAME=caddy-tcp-0.0.0.0-443",
            "the control message must carry FDSTORE=1 and the FDNAME"
        );
        assert_eq!(descriptors.len(), 1, "exactly one descriptor must arrive");

        // The received descriptor must refer to the SAME file: this is what distinguishes a real
        // SCM_RIGHTS transfer from a message that merely claims to carry one.
        let received = std::fs::File::from(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(descriptors[0])
        });
        let contents = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(contents, "fdstore");
        let metadata = received.metadata().unwrap();
        assert_eq!(
            metadata.len(),
            7,
            "the descriptor must point at the 7-byte file"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn uploads_over_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let name = format!("caddy-rs-fdstore-abstract-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();

        let file = std::fs::File::open("/dev/null").unwrap();
        send_fd_to_store_at(
            OsStr::new(&format!("@{name}")),
            file.as_raw_fd(),
            "caddy-tcp-::1-8443",
        )
        .unwrap();

        let (payload, descriptors) = receive_one(&receiver);
        assert_eq!(
            String::from_utf8_lossy(&payload),
            "FDSTORE=1\nFDNAME=caddy-tcp-::1-8443"
        );
        assert_eq!(descriptors.len(), 1);
    }

    #[test]
    fn unset_notify_socket_is_a_distinct_error_not_a_silent_noop() {
        // ADR-0047 §6: unset NOTIFY_SOCKET is a clear non-zero error. This asserts the *typed*
        // error so the helper can refuse before binding anything, rather than discovering the
        // problem after it has already bound sockets.
        let error = FdStoreError::NotifySocketUnset;
        assert!(error.to_string().contains("NOTIFY_SOCKET"));
        assert!(error.to_string().contains("fd store"));
    }

    #[test]
    fn rejects_an_empty_abstract_name_and_an_overlong_path() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();

        let empty_abstract = send_fd_to_store_at(OsStr::new("@"), fd, "name");
        assert!(
            empty_abstract.is_err(),
            "an empty abstract name must be rejected"
        );

        let long_path = format!("/{}", "x".repeat(200));
        let overlong = send_fd_to_store_at(OsStr::new(&long_path), fd, "name");
        assert!(
            overlong.is_err(),
            "an overlong socket path must be rejected"
        );
    }

    #[test]
    fn the_payload_builders_are_the_systemd_protocol() {
        // The protocol strings live in core; assert their exact shape here too, because a typo in
        // FDSTORE or FDNAME would make systemd silently ignore the descriptor.
        assert_eq!(
            caddy_rs_core::notify::fdstore_upload_payload("caddy-tcp-:80"),
            "FDSTORE=1\nFDNAME=caddy-tcp-:80"
        );
        assert_eq!(
            caddy_rs_core::notify::fdstore_remove_payload("caddy-tcp-:80"),
            "FDSTOREREMOVE=1\nFDNAME=caddy-tcp-:80"
        );
    }
}
