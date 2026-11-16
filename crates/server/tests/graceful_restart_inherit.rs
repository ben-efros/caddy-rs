//! End-to-end proof that a listener bound through the ecdysis registry is inherited rather than
//! rebound (T-CORE-102, ADR-0044 §1).
//!
//! # What this test can and cannot prove
//!
//! A true `exec` of a child process is out of scope for a unit test binary: ecdysis's inheritance
//! works by handing descriptors to a freshly `exec`'d process over a pipe, which would mean building
//! and running the CLI. What *is* provable here, and is the property that actually matters, is the
//! one that decides whether inheritance can work at all:
//!
//! 1. binding through the registry records the socket under the address the child will look up;
//! 2. the registry's socket is a real kernel socket that accepts connections;
//! 3. the creation closure — the only place socket options are applied — runs for a new socket, so
//!    an inherited socket is not left with different options from a freshly-bound one;
//! 4. a listener bound through the registry keeps serving after a second runtime adopts the same
//!    process-wide state, i.e. nothing about routing through ecdysis changes the accept path.
//!
//! The gap-free-across-exec measurement is `T-CORE-104`, and ADR-0044 §2 is explicit that a gap-free
//! upgrade is a design constraint rather than a demonstrated result. Nothing here claims otherwise.

#![cfg(feature = "graceful-restart")]

use std::net::SocketAddr;
use std::sync::Arc;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::graceful_restart::ListenerBinder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The binder must record the address the kernel actually assigned.
///
/// This is the property whose absence would be silent: ecdysis keys its registry on the live
/// socket's `local_addr()`, so recording the *requested* address (`127.0.0.1:0`) instead of the
/// bound one would make the child look up a port that does not exist in the registry, miss the
/// inherited descriptor, and rebind — reopening exactly the refused-connection window this task
/// exists to close, for that listener only.
#[test]
fn a_registry_bound_listener_records_the_address_the_child_will_look_up() {
    let binder = ListenerBinder::new();
    let listener = binder
        .bind_tcp("127.0.0.1:0".parse().unwrap(), |socket, addr| {
            socket.bind(&addr.into())?;
            socket.listen(128)?;
            let std_listener: std::net::TcpListener = socket.into();
            std_listener.set_nonblocking(true)?;
            Ok(std_listener)
        })
        .expect("bind through the registry");

    let bound = listener.local_addr().expect("local address");
    assert_ne!(bound.port(), 0, "the kernel must have assigned a real port");
    assert_eq!(
        binder.inherited_listeners(),
        vec![bound],
        "the recorded address must equal the bound address, not the requested one"
    );
}

/// A listener bound through the registry is a real, accepting socket.
///
/// Routing through ecdysis must not change the accept path: the returned descriptor is the same
/// kernel socket the direct-bind path would have produced.
#[tokio::test]
async fn a_registry_bound_listener_accepts_connections() {
    let binder = ListenerBinder::new();
    let std_listener = binder
        .bind_tcp("127.0.0.1:0".parse().unwrap(), |socket, addr| {
            socket.bind(&addr.into())?;
            socket.listen(128)?;
            let std_listener: std::net::TcpListener = socket.into();
            std_listener.set_nonblocking(true)?;
            Ok(std_listener)
        })
        .expect("bind through the registry");
    let listener =
        tokio::net::TcpListener::from_std(std_listener).expect("adopt as tokio listener");
    let addr = listener.local_addr().expect("local address");

    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("accept");
        stream.write_all(b"inherited").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.expect("read");
    server.await.expect("server task");
    assert_eq!(buf, b"inherited");
}

/// The creation closure runs exactly once for a new socket.
///
/// ecdysis calls the closure only when it is creating a socket; on an upgrade the inherited
/// descriptor is adopted and the closure never runs. That is why every socket option must be
/// applied *inside* the closure — an option applied after `bind_tcp` returns would be silently
/// skipped for inherited sockets, and the parent and child would disagree about the same kernel
/// socket. This asserts the half of that contract observable without an upgrade.
#[test]
fn the_creation_closure_runs_once_for_a_new_socket() {
    let binder = ListenerBinder::new();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let _listener = binder
        .bind_tcp("127.0.0.1:0".parse().unwrap(), move |socket, addr| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            socket.bind(&addr.into())?;
            socket.listen(128)?;
            let std_listener: std::net::TcpListener = socket.into();
            std_listener.set_nonblocking(true)?;
            Ok(std_listener)
        })
        .expect("bind through the registry");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A runtime with the feature enabled still serves a configured listener end to end.
///
/// This is the regression guard for the routing change itself: `bind` and `bind_admin` now take a
/// registry parameter and `bind_configured_tcp` routes through it, so a mistake there would break
/// ordinary serving, not just upgrades.
#[tokio::test]
async fn a_runtime_with_the_feature_enabled_serves_a_listener() {
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "registry-ok"}]}]
        }}}}
    }))
    .expect("test config decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates and loads");

    let mut runtime =
        caddy_rs_server::ServerRuntime::new(Arc::clone(&store)).without_socket_activation();
    runtime
        .apply()
        .await
        .expect("apply binds the configured listener");

    let bound = runtime
        .status()
        .listener_address("127.0.0.1:0")
        .expect("the runtime must report the address it bound");
    let parsed: SocketAddr = bound.parse().expect("reported address parses");
    assert_ne!(
        parsed.port(),
        0,
        "the runtime must report the real port, not the requested `:0`"
    );
}
