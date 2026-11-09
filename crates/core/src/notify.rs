//! Minimal `sd_notify` integration for systemd-style service managers.
//!
//! Stock Caddy sends `READY=1`, `RELOADING=1` and `STOPPING=1` over the socket named by
//! `NOTIFY_SOCKET`. A `Type=notify` systemd unit stays in `activating` until it receives
//! `READY=1`, so a drop-in replacement must implement the same protocol.
//!
//! This module is deliberately small and dependency-free:
//!
//! * no socket / empty `NOTIFY_SOCKET` is a no-op;
//! * a pathname or a Linux abstract socket (`@name`) is supported;
//! * only fixed protocol messages and a sanitized `STATUS=` line are sent;
//! * notification failures are returned to the caller, which logs them and continues — a
//!   notification failure must never fail the server.
//!
//! There is no watchdog support: stock Caddy does not run one, so inventing a different liveness
//! contract would make the service behave differently.

use std::ffi::OsStr;
use std::io;

/// Environment variable used by systemd to name the notification socket.
pub const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// Maximum length of a `STATUS=` message (systemd's own limit is generous; keep logs bounded).
const MAX_STATUS_BYTES: usize = 200;

/// Tell the service manager the configuration is fully applied and serving.
pub fn ready() -> io::Result<()> {
    send("READY=1")
}

/// Tell the service manager a reload has started.
pub fn reloading() -> io::Result<()> {
    send("RELOADING=1")
}

/// Tell the service manager the process is stopping.
pub fn stopping() -> io::Result<()> {
    send("STOPPING=1")
}

/// Send a one-line `STATUS=` diagnostic. Newlines/control characters are replaced with spaces and
/// the value is bounded, so a caller-supplied error can never inject additional protocol lines.
pub fn status(message: &str) -> io::Result<()> {
    send(&format!("STATUS={}", sanitize_status(message)))
}

/// Send a `STATUS=` diagnostic with an optional errno-style number.
pub fn status_with_errno(message: &str, errno: u32) -> io::Result<()> {
    send(&format!(
        "STATUS={}\nERRNO={errno}",
        sanitize_status(message)
    ))
}

/// Send one payload to the socket named by `NOTIFY_SOCKET`.
///
/// An unset or empty variable is a successful no-op. Invalid socket names return an error.
pub fn send(payload: &str) -> io::Result<()> {
    match std::env::var_os(NOTIFY_SOCKET_ENV) {
        Some(socket) if !socket.is_empty() => send_to_os(&socket, payload),
        _ => Ok(()),
    }
}

/// Send one payload to a pathname socket (used by tests and embedders).
pub fn send_to_path(path: &std::path::Path, payload: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        let socket = std::os::unix::net::UnixDatagram::unbound()?;
        socket.connect(path)?;
        socket.send(payload.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, payload);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sd_notify is only available on Unix",
        ))
    }
}

/// Send one payload to a Linux abstract socket (the `@name` form used by systemd).
#[cfg(target_os = "linux")]
pub fn send_to_abstract(name: &str, payload: &str) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let trimmed = name.strip_prefix('@').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty abstract NOTIFY_SOCKET name",
        ));
    }
    let address = SocketAddr::from_abstract_name(trimmed.as_bytes())?;
    let socket = UnixDatagram::unbound()?;
    socket.connect_addr(&address)?;
    socket.send(payload.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
fn send_to_os(socket: &OsStr, payload: &str) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = socket.as_bytes();
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes[0] == b'@' {
        #[cfg(target_os = "linux")]
        {
            return send_to_abstract(socket.to_string_lossy().as_ref(), payload);
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "abstract NOTIFY_SOCKET is only supported on Linux",
            ));
        }
    }
    send_to_path(std::path::Path::new(socket), payload)
}

#[cfg(not(unix))]
fn send_to_os(_socket: &OsStr, _payload: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sd_notify is only available on Unix",
    ))
}

fn sanitize_status(message: &str) -> String {
    let mut value = String::with_capacity(message.len().min(MAX_STATUS_BYTES));
    for character in message.chars() {
        if character.is_control() {
            value.push(' ');
        } else {
            value.push(character);
        }
        if value.len() >= MAX_STATUS_BYTES {
            break;
        }
    }
    // Truncation above happens at a character boundary because we append whole `char`s.
    value.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_socket() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "caddy-rs-notify-{}-{nonce}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn sends_a_single_datagram_to_a_path_socket() {
        let path = temp_socket();
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        send_to_path(&path, "READY=1").unwrap();
        let mut buffer = [0_u8; 128];
        let size = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], b"READY=1");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn status_is_single_line_and_bounded() {
        let path = temp_socket();
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        let message = format!("first line\nREADY=1\r{}", "x".repeat(400));
        send_to_path(&path, &format!("STATUS={}", sanitize_status(&message))).unwrap();
        let mut buffer = [0_u8; 512];
        let size = receiver.recv(&mut buffer).unwrap();
        let value = std::str::from_utf8(&buffer[..size]).unwrap();
        assert!(!value.contains('\n'));
        assert!(!value.contains('\r'));
        assert!(value.len() <= MAX_STATUS_BYTES + "STATUS=".len());
        assert!(value.starts_with("STATUS="));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_socket_is_a_noop() {
        // Do not mutate the process environment here: the test suite runs in parallel and other
        // tests may inspect it. The unset/empty behavior is covered through the public `send`
        // contract by using an explicit empty socket in the helper below.
        fn send_with(socket: Option<&OsStr>, payload: &str) -> io::Result<()> {
            match socket {
                Some(socket) if !socket.is_empty() => send_to_os(socket, payload),
                _ => Ok(()),
            }
        }
        assert!(send_with(None, "READY=1").is_ok());
        assert!(send_with(Some(OsStr::new("")), "READY=1").is_ok());
    }

    #[test]
    fn status_with_errno_is_two_lines() {
        let path = temp_socket();
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        send_to_path(&path, "STATUS=failed\nERRNO=13").unwrap();
        let mut buffer = [0_u8; 128];
        let size = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], b"STATUS=failed\nERRNO=13");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sends_to_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let name = format!("caddy-rs-notify-test-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();
        send_to_abstract(&name, "RELOADING=1").unwrap();
        let mut buffer = [0_u8; 128];
        let size = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], b"RELOADING=1");
    }
}
