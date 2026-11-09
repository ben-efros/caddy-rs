//! Grace-period shutdown semantics: graceful drain, forced close after the grace period,
//! rejection of new connections, `/stop` handling, and upgrade-tunnel behaviour.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_test_support::{free_port, retry_addr_in_use};

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
async fn slow_request_completes_with_eternal_grace_period() {
    // Caddy's `grace_period` is zero/absent: `modules/caddyhttp/app.go` then logs "servers
    // shutting down with eternal grace period" and calls `Shutdown(context.Background())`, so an
    // in-flight request must be allowed to finish rather than being force-closed at once.
    let upstream = spawn_slow_upstream(Duration::from_millis(300));
    let (runtime, address) = start(config(&upstream, None, None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = send_get(address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    shutdown_tx.send(true).expect("signal shutdown");

    let response = read_all(&mut client, Duration::from_secs(5)).await;
    assert!(
        body_contains(&response, b"slow-ok"),
        "eternal grace period must let the in-flight request finish: {:?}",
        String::from_utf8_lossy(&response)
    );
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("runtime must return after the eternal-grace drain");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "shutdown must have waited for the slow response, took {:?}",
        started.elapsed()
    );
    assert!(
        TcpStream::connect(address).await.is_err(),
        "listener must be closed after shutdown"
    );
}

#[tokio::test]
async fn upgraded_tunnel_does_not_hang_eternal_grace_period() {
    // Go's `http.Server.Shutdown` (which Caddy uses for the grace period) neither closes nor waits
    // for hijacked connections; without a configured grace period the runtime must drain ordinary
    // connections and then close upgraded tunnels instead of hanging forever.
    let upstream = spawn_upgrade_echo_upstream();
    let (runtime, address) = start(config(&upstream, None, None)).await;
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
    assert!(head.starts_with(b"HTTP/1.1 101"), "upgrade must succeed");

    shutdown_tx.send(true).expect("signal shutdown");
    let started = std::time::Instant::now();
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("eternal grace must not wait for a hijacked tunnel");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "hijacked tunnel must not block eternal-grace shutdown, took {:?}",
        started.elapsed()
    );
    let tail = read_all(&mut client, Duration::from_secs(2)).await;
    assert!(tail.is_empty(), "tunnel must be closed by the forced stop");
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
    let upstream = spawn_slow_upstream(Duration::from_millis(300));
    // The admin listener needs a stable fixed port for the `run` loop; retry the initial bind on
    // AddrInUse with a freshly allocated one.
    let (runtime, address, admin_port) = retry_addr_in_use(|| {
        let admin_port = free_port();
        let config = config_with_admin(&upstream, "1s", admin_port);
        let store = Arc::new(GenerationStore::with_builtin_registry());
        store.load(config).expect("config loads");
        let mut runtime = ServerRuntime::new(store);
        async move {
            runtime.apply().await?;
            let address = runtime
                .listener_address("127.0.0.1:0")
                .expect("listener bound");
            Ok::<_, caddy_rs_server::Error>((runtime, address, admin_port))
        }
    })
    .await
    .expect("runtime applies");
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

fn config_with_listen(
    upstream: &str,
    listen: &str,
    grace: Option<&str>,
    shutdown_delay: Option<&str>,
) -> Config {
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
            "listen": [listen],
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

#[tokio::test]
async fn reload_honors_shutdown_delay_and_grace_for_closing_listeners() {
    // Caddy's `App.stop` (called for a config reload, not only process exit) sleeps
    // `shutdown_delay` while the closing listener keeps accepting, then bounds the drain with the
    // grace-period context (`modules/caddyhttp/app.go`). A reload itself does not wait for the
    // grace period, but the closing listener's over-grace request is force-closed.
    let upstream = spawn_slow_upstream(Duration::from_secs(2));
    let old_port = free_port();
    let new_port = free_port();
    let old_config = config_with_listen(
        &upstream,
        &format!("127.0.0.1:{old_port}"),
        Some("300ms"),
        Some("200ms"),
    );
    let new_config = config_with_listen(
        &upstream,
        &format!("127.0.0.1:{new_port}"),
        Some("300ms"),
        None,
    );

    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(old_config).expect("old config loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("old config applies");
    let old_address = runtime
        .listener_address(&format!("127.0.0.1:{old_port}"))
        .expect("old listener bound");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut old_client = send_get(old_address, "/slow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let load_started = std::time::Instant::now();
    store.load(new_config).expect("new config loads");
    // The reload applies on the runtime loop's next heartbeat.
    let new_address: SocketAddr = format!("127.0.0.1:{new_port}")
        .parse()
        .expect("new address");
    let mut new_served = false;
    for _ in 0..200 {
        if TcpStream::connect(new_address).await.is_ok() {
            new_served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(new_served, "reloaded listener must start serving");

    let response = read_all(&mut old_client, Duration::from_secs(4)).await;
    let closing_elapsed = load_started.elapsed();
    assert!(
        closing_elapsed >= Duration::from_millis(180),
        "closing listener must honor shutdown_delay before draining, took {closing_elapsed:?}"
    );
    assert!(
        !body_contains(&response, b"slow-ok"),
        "over-grace request on the closing listener must be force-closed: {:?}",
        String::from_utf8_lossy(&response)
    );

    // The new listener keeps serving after the old one is gone.
    assert!(TcpStream::connect(old_address).await.is_err());
    let mut client = send_get(new_address, "/fast").await;
    let response = read_all(&mut client, Duration::from_secs(3)).await;
    assert!(
        body_contains(&response, b"slow-ok"),
        "new listener must serve after the reload: {:?}",
        String::from_utf8_lossy(&response)
    );

    shutdown_tx.send(true).expect("shutdown");
    let joined = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("runtime must return");
    joined.expect("runtime task").expect("run returns Ok");
}

#[tokio::test]
async fn fifty_concurrent_slow_requests_drain_with_eternal_grace() {
    let upstream = spawn_slow_upstream(Duration::from_millis(250));
    let (runtime, address) = start(config(&upstream, None, None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut clients = Vec::new();
    for _ in 0..50 {
        clients.push(send_get(address, "/slow").await);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_tx.send(true).expect("signal shutdown");

    let mut tasks = Vec::new();
    for mut client in clients {
        tasks.push(tokio::spawn(async move {
            read_all(&mut client, Duration::from_secs(8)).await
        }));
    }
    let mut completed = 0;
    for task in tasks {
        let response = task.await.expect("client task");
        assert!(
            body_contains(&response, b"slow-ok"),
            "every in-flight request must finish during the eternal grace period: {:?}",
            String::from_utf8_lossy(&response)
        );
        completed += 1;
    }
    assert_eq!(completed, 50);

    let joined = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("runtime must return after all connections drain");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn forced_shutdown_aborts_fifty_in_flight_requests_and_releases_listener() {
    let upstream = spawn_slow_upstream(Duration::from_secs(5));
    let (runtime, address) = start(config(&upstream, Some("10s"), None)).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (force_tx, force_rx) = watch::channel(false);
    let running = tokio::spawn(async move { runtime.run_with_force(shutdown_rx, force_rx).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut clients = Vec::new();
    for _ in 0..50 {
        clients.push(send_get(address, "/slow").await);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown_tx.send(true).expect("first signal");
    tokio::time::sleep(Duration::from_millis(100)).await;
    force_tx.send(true).expect("second signal");

    let started = std::time::Instant::now();
    let joined = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("forced shutdown must return promptly");
    joined.expect("runtime task").expect("run returns Ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "forced shutdown must not wait for the 10s grace period, took {:?}",
        started.elapsed()
    );

    for mut client in clients {
        let response = read_all(&mut client, Duration::from_secs(2)).await;
        assert!(
            !body_contains(&response, b"slow-ok"),
            "forced shutdown must abort in-flight requests"
        );
    }
    // The listener socket and its accept task are released, so the same address can be rebound.
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpListener::bind(address),
    )
    .await
    .expect("listener address must be released after forced shutdown")
    .expect("rebinding the released address must succeed");
}
