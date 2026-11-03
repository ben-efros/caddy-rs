//! Grace-period shutdown semantics: graceful drain, forced close after the grace period,
//! rejection of new connections, `/stop` handling, and upgrade-tunnel behaviour.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Raw HTTP upstream that reads one request, sleeps `delay`, then answers `200 slow-ok`.
fn spawn_slow_upstream(delay: Duration) -> String {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("upstream runtime");
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
            let address = listener.local_addr().expect("upstream address").to_string();
            ready_tx.send(address).expect("ready");
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    tokio::time::sleep(delay).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nslow-ok",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
    });
    ready_rx.recv().expect("upstream address")
}

/// Raw HTTP upstream that answers `101 Switching Protocols` and echoes bytes afterwards.
fn spawn_upgrade_echo_upstream() -> String {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("upstream runtime");
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
            let address = listener.local_addr().expect("upstream address").to_string();
            ready_tx.send(address).expect("ready");
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                        )
                        .await;
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
    });
    ready_rx.recv().expect("upstream address")
}

fn config(upstream: &str, grace: Option<&str>, shutdown_delay: Option<&str>) -> Config {
    let mut http = serde_json::Map::new();
    if let Some(grace) = grace {
        http.insert("grace_period".into(), serde_json::json!(grace));
    }
    if let Some(delay) = shutdown_delay {
        http.insert("shutdown_delay".into(), serde_json::json!(delay));
    }
    http.insert(
        "servers".into(),
        serde_json::json!({"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream}]
            }]}]
        }}),
    );
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": http}
    }))
    .expect("graceful shutdown config decodes")
}

fn config_with_admin(upstream: &str, grace: &str, admin_port: u16) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"listen": format!("127.0.0.1:{admin_port}")},
        "apps": {"http": {
            "grace_period": grace,
            "servers": {"srv0": {
                "listen": ["127.0.0.1:0"],
                "routes": [{"handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": upstream}]
                }]}]
            }}
        }}
    }))
    .expect("admin graceful shutdown config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config loads");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

async fn send_get(address: SocketAddr, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.expect("client connect");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write request");
    stream
}

async fn read_all(stream: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    let mut response = Vec::new();
    let _ = tokio::time::timeout(timeout, stream.read_to_end(&mut response)).await;
    response
}

async fn read_head(stream: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    let mut head = Vec::new();
    let _ = tokio::time::timeout(timeout, async {
        let mut byte = [0u8; 1];
        while stream.read_exact(&mut byte).await.is_ok() {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    })
    .await;
    head
}

async fn read_exact(stream: &mut TcpStream, length: usize, timeout: Duration) -> Vec<u8> {
    let mut buffer = vec![0u8; length];
    let _ = tokio::time::timeout(timeout, stream.read_exact(&mut buffer)).await;
    buffer
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn body_contains(response: &[u8], needle: &[u8]) -> bool {
    response
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn slow_request_completes_within_grace_period() {
    let upstream = spawn_slow_upstream(Duration::from_millis(300));
    let (runtime, address) = start(config(&upstream, Some("2s"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = send_get(address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // First SIGTERM: stop accepting and drain in-flight work for up to 2s.
    shutdown_tx.send(true).expect("signal shutdown");

    let response = read_all(&mut client, Duration::from_secs(5)).await;
    assert!(
        body_contains(&response, b"slow-ok"),
        "in-flight request must finish within the grace period: {:?}",
        String::from_utf8_lossy(&response)
    );
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must return after the drain");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        TcpStream::connect(address).await.is_err(),
        "listener must be closed after shutdown"
    );
}

#[tokio::test]
async fn over_grace_connection_is_force_closed() {
    let upstream = spawn_slow_upstream(Duration::from_secs(5));
    let (runtime, address) = start(config(&upstream, Some("150ms"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = send_get(address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_tx.send(true).expect("signal shutdown");

    let started = std::time::Instant::now();
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must return after the grace period");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "grace period must bound shutdown, took {:?}",
        started.elapsed()
    );
    let response = read_all(&mut client, Duration::from_secs(2)).await;
    assert!(
        !body_contains(&response, b"slow-ok"),
        "a request exceeding the grace period must be closed, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        TcpStream::connect(address).await.is_err(),
        "listener must be closed after shutdown"
    );
}

#[tokio::test]
async fn new_connections_are_rejected_after_shutdown_signal() {
    let upstream = spawn_slow_upstream(Duration::from_millis(50));
    let (runtime, address) = start(config(&upstream, Some("2s"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown_tx.send(true).expect("signal shutdown");

    // The accept loop stops immediately (before the grace-period drain finishes).
    let mut closed = false;
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(closed, "new connections must be rejected during shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(3), running).await;
}

#[tokio::test]
async fn second_signal_forces_immediate_shutdown() {
    let upstream = spawn_slow_upstream(Duration::from_secs(5));
    let (runtime, address) = start(config(&upstream, Some("10s"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (force_tx, force_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run_with_force(shutdown_rx, force_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut client = send_get(address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    shutdown_tx.send(true).expect("first signal");
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Second SIGTERM: skip the remaining grace period and close connections.
    force_tx.send(true).expect("second signal");
    let started = std::time::Instant::now();
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("forced shutdown must return promptly");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "second signal must skip the 10s grace period, took {:?}",
        started.elapsed()
    );
    let response = read_all(&mut client, Duration::from_secs(2)).await;
    assert!(!body_contains(&response, b"slow-ok"));
}

#[tokio::test]
async fn admin_stop_drains_within_grace_period() {
    let admin_port = free_loopback_port();
    let upstream = spawn_slow_upstream(Duration::from_millis(300));
    let (runtime, address) = start(config_with_admin(&upstream, "1s", admin_port)).await;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = send_get(address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // POST /stop: Caddy unloads the generation and exits, but graceful shutdown still drains.
    let mut admin = TcpStream::connect(("127.0.0.1", admin_port))
        .await
        .expect("admin connect");
    admin
        .write_all(b"POST /stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .expect("admin stop");
    let admin_response = read_all(&mut admin, Duration::from_secs(3)).await;
    assert!(
        body_contains(&admin_response, b"200"),
        "POST /stop must succeed: {:?}",
        String::from_utf8_lossy(&admin_response)
    );

    let response = read_all(&mut client, Duration::from_secs(4)).await;
    assert!(
        body_contains(&response, b"slow-ok"),
        "in-flight request must drain after /stop: {:?}",
        String::from_utf8_lossy(&response)
    );
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must exit after /stop");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn upgraded_tunnel_survives_grace_period_then_is_closed() {
    let upstream = spawn_upgrade_echo_upstream();
    let (runtime, address) = start(config(&upstream, Some("700ms"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("write upgrade request");
    let head = read_head(&mut client, Duration::from_secs(2)).await;
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "upgrade must succeed: {:?}",
        String::from_utf8_lossy(&head)
    );
    client.write_all(b"ping").await.expect("write ping");
    assert_eq!(
        read_exact(&mut client, 4, Duration::from_secs(2)).await,
        b"ping"
    );

    shutdown_tx.send(true).expect("signal shutdown");
    // During the grace period the upgraded tunnel is still functional.
    tokio::time::sleep(Duration::from_millis(150)).await;
    client.write_all(b"pong").await.expect("write pong");
    assert_eq!(
        read_exact(&mut client, 4, Duration::from_secs(2)).await,
        b"pong",
        "upgraded tunnel must stay alive during the grace period"
    );

    // After the grace period the tunnel is force-closed and the runtime returns.
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must return after grace");
    joined.expect("runtime task").expect("run returns Ok");
    let tail = read_all(&mut client, Duration::from_secs(2)).await;
    assert!(tail.is_empty(), "tunnel must be closed after grace");
}

#[tokio::test]
async fn shutdown_delay_keeps_listeners_open_before_grace() {
    // Caddy's `shutdown_delay` keeps the server accepting during the delay (allowing a load
    // balancer to stop sending traffic) before the grace period starts.
    let upstream = spawn_slow_upstream(Duration::from_millis(10));
    let (runtime, address) = start(config(&upstream, Some("1s"), Some("400ms"))).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    shutdown_tx.send(true).expect("signal shutdown");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut client = send_get(address, "/during-delay").await;
    let response = read_all(&mut client, Duration::from_secs(2)).await;
    assert!(
        body_contains(&response, b"slow-ok"),
        "listeners must keep serving during shutdown_delay: {:?}",
        String::from_utf8_lossy(&response)
    );

    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must exit after delay+grace");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(TcpStream::connect(address).await.is_err());
}
