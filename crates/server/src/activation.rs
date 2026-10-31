//! systemd-style socket activation (plan task T-HTTP-041).
//!
//! systemd can create listening sockets before the service starts and pass them to the process as
//! inherited file descriptors, following the `sd_listen_fds(3)` convention:
//!
//! * `LISTEN_PID` — the process id the descriptors belong to; ignored when it is not this process
//!   (systemd's own check, so forked children do not re-adopt the parent's sockets),
//! * `LISTEN_FDS` — the number of descriptors; they are `LISTEN_FDS` consecutive descriptors
//!   starting at [`SD_LISTEN_FDS_START`] (fd 3),
//! * `LISTEN_FDNAMES` — optional colon-separated names for logging and error messages.
//!
//! caddy-rs adopts every inherited socket at startup and serves it through the normal listener
//! pipeline, so the process never binds it. The mapping is by network and local address:
//!
//! * a TCP inherited socket matches a configured `host:port` listener when the ports are equal and
//!   the hosts are compatible (exact IP, resolved hostname, IPv4-mapped IPv6 normalized);
//! * a wildcard configured listener (`:80`) matches an inherited wildcard socket (`0.0.0.0:80` or
//!   `[::]:80`), and two wildcard sockets match regardless of family because both claim every
//!   interface;
//! * a Unix inherited socket matches a configured `unix//path` listener when the paths are equal.
//!
//! Mismatch policy:
//!
//! * a configured listener with no matching inherited socket is bound normally (fallback),
//! * an inherited socket not claimed by any configured listener fails the apply with a located
//!   [`crate::error::Error::SocketActivation`] error (a socket passed by the service manager but
//!   never served would silently strand traffic, so it must be loud),
//! * malformed environment values, closed descriptors, descriptors that are not listening sockets
//!   and `LISTEN_FDS`/`LISTEN_FDNAMES` count mismatches all fail loudly with a located error.
//!
//! ## Compatibility
//!
//! Caddy v2.11.7 does not implement socket activation (it has no `LISTEN_FDS` handling), so this
//! is a caddy-rs extension; see `docs/compatibility/BEHAVIOR-DIVERGENCES.md` DIV-0032.
//!
//! ## Unsafe code
//!
//! Adopting an inherited descriptor requires the `FromRawFd` family, which is `unsafe`. The crate
//! denies unsafe code (`#![deny(unsafe_code)]`) and only this module allows it, because adopting
//! file descriptors from the service manager is impossible through safe Rust. Every unsafe block
//! below is annotated with its invariant: the descriptor was validated as an open listening socket
//! by [`inspect_descriptor`] and ownership is transferred exactly once.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use caddy_rs_core::{ListenAddr, Network};

use crate::error::Error;

/// First file descriptor passed by systemd (`SD_LISTEN_FDS_START`).
pub const SD_LISTEN_FDS_START: RawFd = 3;

/// Sanity bound for `LISTEN_FDS`; a larger value is treated as a malformed environment rather than
/// allocated.
pub const MAX_INHERITED_DESCRIPTORS: usize = 4096;

const DEFAULT_SOCKET_NAME: &str = "unknown";

/// A located socket-activation error, converted into [`crate::error::Error`] by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationError {
    path: String,
    message: String,
}

impl ActivationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Located path of the offending value (for example `LISTEN_FDS[1]`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable diagnosis naming the offending value.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "`{}`: {}", self.path, self.message)
    }
}

impl std::error::Error for ActivationError {}

impl From<ActivationError> for Error {
    fn from(error: ActivationError) -> Self {
        Error::SocketActivation {
            path: error.path,
            message: error.message,
        }
    }
}

/// The local address a listening socket is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalSocket {
    /// An Internet socket (`AF_INET` or `AF_INET6`).
    Tcp(SocketAddr),
    /// A filesystem Unix-domain socket (`AF_UNIX`).
    Unix(PathBuf),
}

impl std::fmt::Display for LocalSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalSocket::Tcp(address) => write!(formatter, "TCP {address}"),
            LocalSocket::Unix(path) => write!(formatter, "Unix {}", path.display()),
        }
    }
}

/// One inherited listening socket.
#[derive(Debug)]
pub struct InheritedSocket {
    fd: RawFd,
    index: usize,
    name: String,
    local: LocalSocket,
}

impl InheritedSocket {
    /// The raw file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Zero-based index in the `LISTEN_FDS` sequence (the descriptor is `3 + index`).
    pub fn index(&self) -> usize {
        self.index
    }

    /// Name from `LISTEN_FDNAMES`, or `"unknown"` when the environment did not provide one.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Local address the descriptor is bound to.
    pub fn local(&self) -> &LocalSocket {
        &self.local
    }

    /// Give up ownership of the descriptor so it can be adopted by a listener.
    ///
    /// The caller becomes responsible for closing the descriptor (the listener adopts it).
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl Drop for InheritedSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is owned by this value (see `into_raw_fd`), so closing it here is correct
        // and cannot double-close. A close error on process teardown is not actionable.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// A set of inherited listening sockets, parsed from the process environment or constructed by an
/// embedder/test.
///
/// Ownership of the descriptors is transferred to this value: dropping an unclaimed
/// [`InheritedSocket`] closes it.
#[derive(Debug, Default)]
pub struct SocketActivation {
    sockets: Vec<InheritedSocket>,
}

impl SocketActivation {
    /// Read `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` from the process environment.
    ///
    /// Returns `Ok(None)` when the environment does not describe activation for this process,
    /// which is the normal non-systemd case. Malformed values are located errors.
    pub fn from_env() -> Result<Option<Self>, ActivationError> {
        let listen_pid = optional_env("LISTEN_PID")?;
        let listen_fds = optional_env("LISTEN_FDS")?;
        let listen_fdnames = optional_env("LISTEN_FDNAMES")?;
        Self::from_env_values(
            listen_pid.as_deref(),
            listen_fds.as_deref(),
            listen_fdnames.as_deref(),
            std::process::id(),
        )
    }

    /// Parse activation from explicit environment values.
    ///
    /// `current_pid` is compared against `LISTEN_PID`; tests can pass a synthetic pid.
    pub fn from_env_values(
        listen_pid: Option<&str>,
        listen_fds: Option<&str>,
        listen_fdnames: Option<&str>,
        current_pid: u32,
    ) -> Result<Option<Self>, ActivationError> {
        let Some(descriptors) =
            parse_environment(listen_pid, listen_fds, listen_fdnames, current_pid)?
        else {
            return Ok(None);
        };
        let mut sockets = Vec::with_capacity(descriptors.len());
        for (index, (fd, name)) in descriptors.into_iter().enumerate() {
            let local = inspect_descriptor(fd, &name, &format!("LISTEN_FDS[{index}]"))?;
            sockets.push(InheritedSocket {
                fd,
                index,
                name,
                local,
            });
        }
        Ok(Some(Self { sockets }))
    }

    /// Build an activation set from already-open listening descriptors.
    ///
    /// Used by embedders and tests to inject sockets without process-global environment variables.
    /// Ownership of the descriptors is transferred; on error the descriptors that were inspected
    /// are closed.
    pub fn from_raw_descriptors(
        descriptors: Vec<(RawFd, Option<String>)>,
    ) -> Result<Self, ActivationError> {
        let mut sockets = Vec::with_capacity(descriptors.len());
        for (index, (fd, name)) in descriptors.iter().enumerate() {
            let name = name
                .clone()
                .unwrap_or_else(|| DEFAULT_SOCKET_NAME.to_string());
            match inspect_descriptor(*fd, &name, &format!("activation_fd[{index}]")) {
                Ok(local) => sockets.push(InheritedSocket {
                    fd: *fd,
                    index,
                    name,
                    local,
                }),
                Err(error) => {
                    // The caller handed ownership to us; close the descriptors we have not taken
                    // ownership of yet so an invalid set does not leak file descriptors.
                    for (remaining_fd, _) in &descriptors[index..] {
                        // SAFETY: these descriptors are owned by this function and are not part of
                        // any `InheritedSocket` yet, so closing them exactly once is correct.
                        unsafe {
                            libc::close(*remaining_fd);
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self { sockets })
    }

    /// Number of inherited sockets.
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Whether no sockets were inherited.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// The inherited sockets.
    pub fn sockets(&self) -> &[InheritedSocket] {
        &self.sockets
    }
}

/// Read one optional environment variable, treating non-UTF-8 as a located error.
fn optional_env(name: &str) -> Result<Option<String>, ActivationError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ActivationError::new(
            name,
            "value is not valid UTF-8; systemd always passes UTF-8 values",
        )),
    }
}

/// Parse the `sd_listen_fds` environment convention into `(descriptor, name)` pairs.
///
/// Pure function (no syscalls) so the conventions can be unit-tested without real descriptors.
fn parse_environment(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    listen_fdnames: Option<&str>,
    current_pid: u32,
) -> Result<Option<Vec<(RawFd, String)>>, ActivationError> {
    // `sd_listen_fds` checks LISTEN_PID first: descriptors are not ours in forked children.
    let Some(listen_pid) = listen_pid else {
        return Ok(None);
    };
    let declared_pid: u32 = listen_pid.parse().map_err(|_| {
        ActivationError::new(
            "LISTEN_PID",
            format!("expected a decimal process id, got {listen_pid:?}"),
        )
    })?;
    if declared_pid != current_pid {
        return Ok(None);
    }
    let Some(listen_fds) = listen_fds else {
        return Ok(None);
    };
    let count: usize = listen_fds.parse().map_err(|_| {
        ActivationError::new(
            "LISTEN_FDS",
            format!("expected a non-negative descriptor count, got {listen_fds:?}"),
        )
    })?;
    if count == 0 {
        return Ok(None);
    }
    if count > MAX_INHERITED_DESCRIPTORS {
        return Err(ActivationError::new(
            "LISTEN_FDS",
            format!(
                "descriptor count {count} exceeds the {MAX_INHERITED_DESCRIPTORS} sanity limit"
            ),
        ));
    }

    let names: Vec<String> = match listen_fdnames {
        None => std::iter::repeat_n(DEFAULT_SOCKET_NAME.to_string(), count).collect(),
        Some(value) => {
            let names: Vec<String> = value.split(':').map(str::to_string).collect();
            if names.len() != count {
                return Err(ActivationError::new(
                    "LISTEN_FDNAMES",
                    format!(
                        "lists {} name(s) but LISTEN_FDS declares {count} descriptor(s)",
                        names.len()
                    ),
                ));
            }
            if let Some(position) = names.iter().position(String::is_empty) {
                return Err(ActivationError::new(
                    "LISTEN_FDNAMES",
                    format!("name at position {position} is empty"),
                ));
            }
            names
        }
    };

    Ok(Some(
        names
            .into_iter()
            .enumerate()
            .map(|(index, name)| (SD_LISTEN_FDS_START + index as RawFd, name))
            .collect(),
    ))
}

/// Validate that `fd` is an open listening socket and return its local address.
fn inspect_descriptor(fd: RawFd, name: &str, path: &str) -> Result<LocalSocket, ActivationError> {
    if fd < 0 {
        return Err(ActivationError::new(
            path,
            format!("descriptor {fd} is not a valid file descriptor"),
        ));
    }
    // SAFETY: `fcntl(F_GETFD)` only inspects the descriptor table entry; any integer is accepted
    // and an invalid descriptor reports EBADF instead of touching memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(ActivationError::new(
            path,
            format!(
                "fd {fd} (LISTEN_FDNAMES name `{name}`) is not open: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes an `int` into `accepting` and records its size in `length`;
    // both pointers are valid for the duration of the call.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut accepting as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    };
    if result < 0 {
        return Err(ActivationError::new(
            path,
            format!(
                "fd {fd} is not a socket (SO_ACCEPTCONN failed: {}); \
                 systemd must pass listening sockets",
                io::Error::last_os_error()
            ),
        ));
    }
    if accepting != 1 {
        return Err(ActivationError::new(
            path,
            format!("fd {fd} is a socket but is not listening; cannot accept connections"),
        ));
    }

    socket_local_address(fd).map_err(|error| {
        ActivationError::new(
            path,
            format!("cannot inspect fd {fd} local address: {error}"),
        )
    })
}

/// Read the local address of an open socket descriptor.
fn socket_local_address(fd: RawFd) -> io::Result<LocalSocket> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `getsockname` fills `storage` and records the number of bytes written in `length`.
    // `sockaddr_storage` is the widest sockaddr type, so the buffer cannot be overrun.
    let result = unsafe {
        libc::getsockname(
            fd,
            &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the family determines which sockaddr variant `getsockname` wrote into the
    // zero-initialized storage; `sockaddr_in`/`sockaddr_in6` are smaller than `sockaddr_storage`,
    // so the casts are in bounds.
    unsafe {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                let address =
                    &*(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
                let port = u16::from_be(address.sin_port);
                Ok(LocalSocket::Tcp(SocketAddr::from((ip, port))))
            }
            libc::AF_INET6 => {
                let address =
                    &*(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(address.sin6_addr.s6_addr);
                let port = u16::from_be(address.sin6_port);
                Ok(LocalSocket::Tcp(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    u32::from_be(address.sin6_flowinfo),
                    address.sin6_scope_id,
                ))))
            }
            libc::AF_UNIX => {
                let address =
                    &*(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_un);
                let bytes: Vec<u8> = address
                    .sun_path
                    .iter()
                    .map(|byte| *byte as u8)
                    .take_while(|byte| *byte != 0)
                    .collect();
                if bytes.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "abstract Unix-domain sockets are not supported by caddy-rs listener addresses",
                    ));
                }
                use std::os::unix::ffi::OsStringExt;
                Ok(LocalSocket::Unix(PathBuf::from(OsString::from_vec(bytes))))
            }
            family => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported socket address family {family}"),
            )),
        }
    }
}

/// A resolved mapping from configured listen addresses to inherited sockets.
#[derive(Debug, Default)]
pub struct ActivationPlan {
    claims: BTreeMap<String, InheritedSocket>,
    inherited: usize,
}

impl ActivationPlan {
    /// Number of inherited sockets the plan started with.
    pub fn inherited(&self) -> usize {
        self.inherited
    }

    /// Whether any inherited socket is still waiting to be adopted.
    pub fn has_claims(&self) -> bool {
        !self.claims.is_empty()
    }

    /// Take the inherited socket claimed for one configured listen address, if any.
    pub fn claim(&mut self, listen: &str) -> Option<InheritedSocket> {
        self.claims.remove(listen)
    }

    /// Configured listen addresses that will be served from inherited sockets.
    pub fn claimed_listeners(&self) -> impl Iterator<Item = &str> {
        self.claims.keys().map(String::as_str)
    }
}

/// Map inherited sockets onto configured listen addresses.
///
/// Listen addresses are processed in sorted order so the mapping is deterministic. Every inherited
/// socket must be claimed; an unclaimed socket is a located error because it usually means the
/// systemd unit and the Caddy configuration disagree.
pub fn plan_activation<'a, I>(
    listens: I,
    activation: SocketActivation,
) -> Result<ActivationPlan, ActivationError>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut listen_keys: Vec<&String> = listens.into_iter().collect();
    listen_keys.sort();

    let mut slots: Vec<Option<InheritedSocket>> =
        activation.sockets.into_iter().map(Some).collect();
    let inherited = slots.len();
    let mut claims = BTreeMap::new();

    for listen in listen_keys {
        let parsed = ListenAddr::parse(listen).map_err(|reason| {
            ActivationError::new(
                "listen",
                format!("cannot parse configured listener `{listen}`: {reason}"),
            )
        })?;
        let matching = slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|socket| listen_matches(&parsed, socket.local()))
        });
        if let Some(index) = matching {
            if let Some(socket) = slots[index].take() {
                claims.insert(listen.clone(), socket);
            }
        }
    }

    let unclaimed: Vec<&InheritedSocket> = slots.iter().flatten().collect();
    if !unclaimed.is_empty() {
        let descriptions: Vec<String> = unclaimed
            .iter()
            .map(|socket| {
                format!(
                    "fd {} ({}) [LISTEN_FDNAMES `{}`]",
                    socket.fd(),
                    socket.local(),
                    socket.name()
                )
            })
            .collect();
        let first = unclaimed[0];
        return Err(ActivationError::new(
            format!("LISTEN_FDS[{}]", first.index()),
            format!(
                "inherited socket(s) not claimed by any configured listener: {}; \
                 configure a matching listen address or stop passing the socket",
                descriptions.join(", ")
            ),
        ));
    }

    Ok(ActivationPlan { claims, inherited })
}

/// Whether a configured listen address can be served by an inherited socket.
fn listen_matches(listen: &ListenAddr, local: &LocalSocket) -> bool {
    match (listen.network, local) {
        (Network::Tcp, LocalSocket::Tcp(address)) => tcp_matches(listen, *address),
        (Network::Unix, LocalSocket::Unix(path)) => Path::new(&listen.address) == path.as_path(),
        _ => false,
    }
}

fn tcp_matches(listen: &ListenAddr, address: SocketAddr) -> bool {
    if listen.port() != Some(address.port()) {
        return false;
    }
    let host = listen.host();
    let inherited_ip = normalize_ip(address.ip());
    if host.is_empty() {
        // A wildcard config listener needs a wildcard socket: serving only one interface when the
        // configuration asked for all of them would silently narrow coverage.
        return inherited_ip.is_unspecified();
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        if normalize_ip(ip).is_unspecified() && inherited_ip.is_unspecified() {
            // `0.0.0.0:80` and `[::]:80` are equivalent full-interface binds.
            return true;
        }
        return normalize_ip(ip) == inherited_ip;
    }
    // Hostname: resolve exactly the way a bind would and require a matching address.
    match (host, address.port()).to_socket_addrs() {
        Ok(resolved) => resolved
            .into_iter()
            .any(|candidate| normalize_ip(candidate.ip()) == inherited_ip),
        Err(_) => false,
    }
}

/// Normalize IPv4-mapped IPv6 addresses so `[::ffff:127.0.0.1]` matches `127.0.0.1`.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(address) => IpAddr::V4(address),
            None => IpAddr::V6(address),
        },
        address => address,
    }
}

/// Adopt an inherited TCP listening socket.
pub(crate) fn adopt_tcp(
    socket: InheritedSocket,
    listen: &str,
) -> Result<tokio::net::TcpListener, Error> {
    let index = socket.index();
    let fd = socket.into_raw_fd();
    // SAFETY: `fd` was validated as an open listening socket by `inspect_descriptor`; ownership
    // was transferred to this function via `into_raw_fd`, so exactly one owner exists.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true).map_err(|error| {
        activation_io_error(
            index,
            listen,
            "cannot make inherited socket non-blocking",
            error,
        )
    })?;
    tokio::net::TcpListener::from_std(listener).map_err(|error| {
        activation_io_error(index, listen, "cannot register inherited socket", error)
    })
}

/// Adopt an inherited Unix-domain listening socket.
pub(crate) fn adopt_unix(
    socket: InheritedSocket,
    listen: &str,
) -> Result<tokio::net::UnixListener, Error> {
    let index = socket.index();
    let fd = socket.into_raw_fd();
    // SAFETY: `fd` was validated as an open listening AF_UNIX socket by `inspect_descriptor`;
    // ownership was transferred to this function via `into_raw_fd`, so exactly one owner exists.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener.set_nonblocking(true).map_err(|error| {
        activation_io_error(
            index,
            listen,
            "cannot make inherited socket non-blocking",
            error,
        )
    })?;
    tokio::net::UnixListener::from_std(listener).map_err(|error| {
        activation_io_error(index, listen, "cannot register inherited socket", error)
    })
}

fn activation_io_error(index: usize, listen: &str, action: &str, error: std::io::Error) -> Error {
    Error::SocketActivation {
        path: format!("LISTEN_FDS[{index}]"),
        message: format!("{action} for configured listener `{listen}`: {error}"),
    }
}

/// Descriptor inspection helper exposed for tests that need fd metadata without adopting the fd.
#[cfg(test)]
fn inspect_for_test(fd: RawFd, index: usize) -> Result<LocalSocket, ActivationError> {
    inspect_descriptor(fd, "test", &format!("test_fd[{index}]"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn descriptor(fd: RawFd, index: usize, local: LocalSocket) -> InheritedSocket {
        InheritedSocket {
            fd,
            index,
            name: format!("name-{index}"),
            local,
        }
    }

    fn activation(sockets: Vec<InheritedSocket>) -> SocketActivation {
        SocketActivation { sockets }
    }

    fn listen_keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    #[test]
    fn parses_sd_listen_fds_conventions() {
        assert_eq!(
            parse_environment(Some("100"), Some("2"), Some("http:admin"), 100).unwrap(),
            Some(vec![(3, "http".to_string()), (4, "admin".to_string())])
        );
        assert_eq!(
            parse_environment(Some("100"), Some("1"), None, 100).unwrap(),
            Some(vec![(3, DEFAULT_SOCKET_NAME.to_string())])
        );
        // LISTEN_PID is checked first, mirroring sd_listen_fds: other processes' fds are ignored.
        assert_eq!(
            parse_environment(Some("999"), Some("2"), Some("a:b"), 100).unwrap(),
            None
        );
        assert_eq!(parse_environment(None, Some("2"), None, 100).unwrap(), None);
        assert_eq!(
            parse_environment(Some("100"), None, None, 100).unwrap(),
            None
        );
        assert_eq!(
            parse_environment(Some("100"), Some("0"), None, 100).unwrap(),
            None
        );
    }

    #[test]
    fn rejects_malformed_activation_environment() {
        let pid = parse_environment(Some("not-a-pid"), Some("1"), None, 100)
            .expect_err("malformed LISTEN_PID");
        assert_eq!(pid.path(), "LISTEN_PID");

        let fds =
            parse_environment(Some("100"), Some("-1"), None, 100).expect_err("negative LISTEN_FDS");
        assert_eq!(fds.path(), "LISTEN_FDS");

        let names = parse_environment(Some("100"), Some("2"), Some("only-one"), 100)
            .expect_err("LISTEN_FDNAMES count mismatch");
        assert_eq!(names.path(), "LISTEN_FDNAMES");
        assert!(names.message().contains("1 name(s)"));

        let empty_name = parse_environment(Some("100"), Some("2"), Some("http:"), 100)
            .expect_err("empty LISTEN_FDNAMES entry");
        assert_eq!(empty_name.path(), "LISTEN_FDNAMES");

        let too_many = parse_environment(
            Some("100"),
            Some(&(MAX_INHERITED_DESCRIPTORS + 1).to_string()),
            None,
            100,
        )
        .expect_err("absurd LISTEN_FDS");
        assert_eq!(too_many.path(), "LISTEN_FDS");
    }

    #[test]
    fn matches_tcp_listeners_by_address() {
        let direct = ListenAddr::parse("127.0.0.1:8080").unwrap();
        assert!(listen_matches(
            &direct,
            &LocalSocket::Tcp("127.0.0.1:8080".parse().unwrap())
        ));
        assert!(!listen_matches(
            &direct,
            &LocalSocket::Tcp("127.0.0.1:8081".parse().unwrap())
        ));
        // A configured host must not silently be served by a wildcard socket.
        assert!(!listen_matches(
            &direct,
            &LocalSocket::Tcp("0.0.0.0:8080".parse().unwrap())
        ));
        // IPv4-mapped IPv6 normalizes to IPv4.
        assert!(listen_matches(
            &direct,
            &LocalSocket::Tcp("[::ffff:127.0.0.1]:8080".parse().unwrap())
        ));

        let wildcard = ListenAddr::parse(":8080").unwrap();
        assert!(listen_matches(
            &wildcard,
            &LocalSocket::Tcp("0.0.0.0:8080".parse().unwrap())
        ));
        assert!(listen_matches(
            &wildcard,
            &LocalSocket::Tcp("[::]:8080".parse().unwrap())
        ));
        assert!(!listen_matches(
            &wildcard,
            &LocalSocket::Tcp("127.0.0.1:8080".parse().unwrap())
        ));

        // Wildcard IP literals of different families are equivalent full-interface binds.
        let v4_wildcard = ListenAddr::parse("0.0.0.0:8080").unwrap();
        assert!(listen_matches(
            &v4_wildcard,
            &LocalSocket::Tcp("[::]:8080".parse().unwrap())
        ));
        let v6_wildcard = ListenAddr::parse("[::]:8080").unwrap();
        assert!(listen_matches(
            &v6_wildcard,
            &LocalSocket::Tcp("0.0.0.0:8080".parse().unwrap())
        ));

        // Network mismatch never matches.
        assert!(!listen_matches(
            &direct,
            &LocalSocket::Unix(PathBuf::from("/run/caddy.sock"))
        ));
    }

    #[test]
    fn matches_hostname_listeners_when_they_resolve() {
        let localhost = ListenAddr::parse("localhost:8080").unwrap();
        let resolved: Vec<IpAddr> = ("localhost", 8080_u16)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .unwrap_or_default();
        if resolved.is_empty() {
            // Some minimal containers have no resolver; the fallback-bind policy handles this.
            assert!(!listen_matches(
                &localhost,
                &LocalSocket::Tcp("127.0.0.1:8080".parse().unwrap())
            ));
        } else {
            for ip in resolved {
                let address = SocketAddr::new(ip, 8080);
                assert!(
                    listen_matches(&localhost, &LocalSocket::Tcp(address)),
                    "localhost:8080 must match {address}"
                );
            }
        }
    }

    #[test]
    fn matches_unix_listeners_by_path() {
        let listen = ListenAddr::parse("unix//run/caddy.sock").unwrap();
        assert!(listen_matches(
            &listen,
            &LocalSocket::Unix(PathBuf::from("/run/caddy.sock"))
        ));
        assert!(!listen_matches(
            &listen,
            &LocalSocket::Unix(PathBuf::from("/run/other.sock"))
        ));
    }

    #[test]
    fn plans_claims_and_falls_back_for_unclaimed_listeners() {
        let listens = listen_keys(&["127.0.0.1:8080", "127.0.0.1:8081"]);
        let activation = activation(vec![descriptor(
            -1,
            0,
            LocalSocket::Tcp("127.0.0.1:8080".parse().unwrap()),
        )]);
        let mut plan = plan_activation(&listens, activation).expect("plan maps the socket");
        assert_eq!(plan.inherited(), 1);
        assert_eq!(
            plan.claimed_listeners().collect::<Vec<_>>(),
            ["127.0.0.1:8080"]
        );
        assert!(plan.claim("127.0.0.1:8080").is_some());
        assert!(plan.claim("127.0.0.1:8081").is_none());
        assert!(!plan.has_claims());
    }

    #[test]
    fn unclaimed_inherited_socket_fails_loudly() {
        let listens = listen_keys(&["127.0.0.1:8080"]);
        let activation = activation(vec![descriptor(
            -1,
            0,
            LocalSocket::Tcp("127.0.0.1:9090".parse().unwrap()),
        )]);
        let error = plan_activation(&listens, activation).expect_err("unmatched fd must fail");
        assert_eq!(error.path(), "LISTEN_FDS[0]");
        assert!(error.message().contains("127.0.0.1:9090"));
        assert!(error.message().contains("not claimed"));
    }

    #[test]
    fn one_socket_is_claimed_once_for_duplicate_addresses() {
        let listens = listen_keys(&[":8080", "0.0.0.0:8080"]);
        let activation = activation(vec![descriptor(
            -1,
            0,
            LocalSocket::Tcp("0.0.0.0:8080".parse().unwrap()),
        )]);
        let plan = plan_activation(&listens, activation).expect("first listener claims the socket");
        // Deterministic sorted order: `0.0.0.0:8080` sorts before `:8080`.
        assert_eq!(
            plan.claimed_listeners().collect::<Vec<_>>(),
            ["0.0.0.0:8080"],
            "exactly one configured listener may claim an inherited socket"
        );
    }

    #[test]
    fn inspects_real_listening_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let expected = listener.local_addr().expect("local address");
        let local = inspect_for_test(listener.as_raw_fd(), 0).expect("inspect listening socket");
        assert_eq!(local, LocalSocket::Tcp(expected));
    }

    #[test]
    fn rejects_descriptors_that_are_not_listening_sockets() {
        let (left, _right) = UnixStream::pair().expect("unix stream pair");
        let error = inspect_for_test(left.as_raw_fd(), 0).expect_err("connected socket rejected");
        assert!(error.message().contains("not listening"), "got: {error}");

        let error = inspect_for_test(-1, 0).expect_err("invalid fd rejected");
        assert!(error.message().contains("not a valid file descriptor"));
    }
}
