//! End-to-end evidence for T-L4-005: a real TCP proxy over loopback, metered per SNI route.
//!
//! The acceptance criterion is that the exported metric values equal the bytes actually proxied,
//! so this test does not compare the metrics against a constant: it proxies a payload of known
//! length through `metered_copy_bidirectional`, reads the echo back, and then reads the *rendered*
//! Prometheus text of the registry, which is what an operator's scrape would return.

use std::sync::Arc;
use std::time::Duration;

use caddy_rs_admin::metrics::MetricsRegistry;
use caddy_rs_l4::actions::{PassthroughConfig, SniAction};
use caddy_rs_l4::metered_copy::{metered_copy_bidirectional, AtomicByteMeter, ByteMeter};
use caddy_rs_l4::metrics::{
    L4Metrics, CONNECTIONS_ACTIVE, HANDSHAKE_DURATION_SECONDS, OTHER_LABEL, READ_BYTES_TOTAL,
    WRITE_BYTES_TOTAL,
};
use caddy_rs_l4::router::{RouteDefinition, SniRouter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Reads a `name{sni="label"}` sample value out of the rendered Prometheus text.
fn sample(rendered: &str, name: &str, label: &str) -> f64 {
    let needle = format!("{name}{{sni=\"{label}\"}} ");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .unwrap_or_else(|| panic!("{needle:?} missing from:\n{rendered}"))
        .trim()
        .parse()
        .expect("sample value parses")
}

/// Accepts one connection and copies it to a loopback "upstream" that echoes every byte back.
async fn run_one_proxy(listener: TcpListener, metrics: Arc<L4Metrics>, router: Arc<SniRouter>) {
    let (client, _peer) = listener.accept().await.expect("client connects");
    // The connection is matched by its SNI label the way the router would after a ClientHello
    // peek; the test drives the route directly so it can assert the label it expected.
    let route = router.lookup(Some("example.com"));
    let connection = metrics.connection(&route).expect("meter registers");
    assert_eq!(
        sample(
            &metrics.registry().render(),
            CONNECTIONS_ACTIVE,
            "example.com"
        ),
        1.0,
        "the active gauge counts the live connection"
    );

    let echo_addr = ECHO_ADDR.get().expect("echo server published").as_str();
    let mut upstream = TcpStream::connect(echo_addr).await.expect("echo connects");
    let mut client = client;
    let meter: Arc<dyn ByteMeter> = Arc::new(connection);
    let totals = metered_copy_bidirectional(&mut client, &mut upstream, &meter)
        .await
        .expect("proxy copy");
    // Dropping the handle decrements the gauge.
    drop(meter);
    assert_eq!(
        totals.a_to_b, totals.b_to_a,
        "echo returns what it received"
    );
}

/// A loopback echo server; every byte read is written straight back.
async fn spawn_echo() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr").to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

// The echo server's address is published through a static so `run_one_proxy` can reach it without
// threading it through the spawn: the test is single-instance and sets it before connecting.
static ECHO_ADDR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exported_byte_counts_equal_the_bytes_actually_proxied() {
    let (echo_addr, echo) = spawn_echo().await;
    ECHO_ADDR.set(echo_addr).expect("one echo server per test");

    let router = Arc::new(
        SniRouter::new(
            vec![RouteDefinition::new(
                "example.com",
                SniAction::Passthrough(
                    PassthroughConfig::new("127.0.0.1:9").expect("valid upstream"),
                ),
            )
            .expect("valid route")],
            SniAction::Passthrough(PassthroughConfig::new("127.0.0.1:9").expect("valid upstream")),
        )
        .expect("valid router"),
    );
    let registry = MetricsRegistry::new();
    let metrics = Arc::new(L4Metrics::new(registry));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let proxy = tokio::spawn(run_one_proxy(listener, Arc::clone(&metrics), router));

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("client connects");
    // A payload that is not a round number of the 16 KiB copy buffer, and bigger than it.
    let request: Vec<u8> = (0..40_000u32).map(|index| (index % 251) as u8).collect();
    client.write_all(&request).await.expect("request written");

    // Read the echo back: the proxied stream is bidirectional, so this proves both directions
    // carried the payload.
    let mut echoed = vec![0u8; request.len()];
    client
        .read_exact(&mut echoed)
        .await
        .expect("echo read back");
    assert_eq!(echoed, request, "the proxy carried the payload unchanged");
    client.shutdown().await.expect("client closes");
    tokio::time::timeout(Duration::from_secs(5), proxy)
        .await
        .expect("proxy finishes")
        .expect("proxy task");

    let rendered = metrics.registry().render();
    // Every byte of the request crossed both directions exactly once: the client-to-upstream
    // copy read it and the upstream-to-client copy wrote it back.
    assert_eq!(
        sample(&rendered, READ_BYTES_TOTAL, "example.com"),
        request.len() as f64,
        "read bytes equal the bytes proxied:\n{rendered}"
    );
    assert_eq!(
        sample(&rendered, WRITE_BYTES_TOTAL, "example.com"),
        request.len() as f64,
        "write bytes equal the bytes proxied back:\n{rendered}"
    );
    assert_eq!(
        sample(&rendered, CONNECTIONS_ACTIVE, "example.com"),
        0.0,
        "the active gauge returns to zero when the connection ends:\n{rendered}"
    );

    echo.abort();
}

#[tokio::test]
async fn wildcard_subdomains_aggregate_into_one_series() {
    let router = SniRouter::new(
        vec![RouteDefinition::new(
            "*.example.com",
            SniAction::Passthrough(PassthroughConfig::new("127.0.0.1:9").expect("valid upstream")),
        )
        .expect("valid wildcard route")],
        SniAction::Passthrough(PassthroughConfig::new("127.0.0.1:9").expect("valid upstream")),
    )
    .expect("valid router");
    let metrics = L4Metrics::new(MetricsRegistry::new());

    // A thousand distinct attacker-chosen SNIs under the wildcard: the cardinality must not grow.
    for index in 0..1000u32 {
        let sni = format!("host{index}.example.com");
        let route = router.lookup(Some(&sni));
        let connection = metrics.connection(&route).expect("meter registers");
        connection.record_read(1);
        drop(connection);
    }
    let rendered = metrics.registry().render();
    let series = rendered
        .lines()
        .filter(|line| line.starts_with(&format!("{READ_BYTES_TOTAL}{{")))
        .count();
    assert_eq!(series, 1, "one series for the whole wildcard:\n{rendered}");
    assert_eq!(sample(&rendered, READ_BYTES_TOTAL, "*.example.com"), 1000.0);
}

#[tokio::test]
async fn unmatched_sni_lands_in_the_other_bucket() {
    let router = SniRouter::empty(SniAction::Passthrough(
        PassthroughConfig::new("127.0.0.1:9").expect("valid upstream"),
    ));
    let metrics = L4Metrics::new(MetricsRegistry::new());
    for sni in ["a.example", "b.example", "c.example"] {
        let route = router.lookup(Some(sni));
        drop(metrics.connection(&route).expect("meter registers"));
    }
    let rendered = metrics.registry().render();
    let series = rendered
        .lines()
        .filter(|line| line.starts_with(&format!("{CONNECTIONS_ACTIVE}{{")))
        .count();
    assert_eq!(
        series, 1,
        "all unmatched SNIs share one series:\n{rendered}"
    );
    assert!(rendered.contains(&format!("sni=\"{OTHER_LABEL}\"")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_atomic_meter_matches_the_copy_totals() {
    // The plain meter is what a proxy uses when no registry is wired; it must agree with the
    // copy's own totals byte for byte. Each side is driven by its own task, and a bounded duplex
    // makes the writer wait for the copier, so the copy must keep both directions moving.
    let (left, left_peer) = tokio::io::duplex(256);
    let (right, right_peer) = tokio::io::duplex(256);
    let meter = Arc::new(AtomicByteMeter::new());
    let shared: Arc<dyn ByteMeter> = Arc::clone(&meter) as Arc<dyn ByteMeter>;
    let copy = tokio::spawn(async move {
        let mut left = left;
        let mut right = right;
        metered_copy_bidirectional(&mut left, &mut right, &shared).await
    });

    // Client: send 5000 bytes, read the 300-byte answer back.
    let client = tokio::spawn(async move {
        let peer = left_peer;
        let payload = vec![7u8; 5000];
        let (mut reader, mut writer) = tokio::io::split(peer);
        let answer = async move {
            let mut small = vec![0u8; 300];
            reader.read_exact(&mut small).await.map(|_| small)
        };
        let send = async move {
            writer.write_all(&payload).await?;
            writer.shutdown().await
        };
        let (sent, answer) = tokio::join!(send, answer);
        sent.expect("client payload");
        answer.expect("answer delivered")
    });
    // Upstream: read the 5000-byte request, answer with 300 bytes.
    let upstream = tokio::spawn(async move {
        let mut peer = right_peer;
        let mut sink = vec![0u8; 5000];
        peer.read_exact(&mut sink).await.expect("request delivered");
        peer.write_all(&[9u8; 300]).await.expect("answer sent");
        peer.shutdown().await.expect("close");
        sink.len()
    });

    assert_eq!(client.await.expect("client task"), vec![9u8; 300]);
    assert_eq!(upstream.await.expect("upstream task"), 5000);
    let totals = copy.await.expect("join").expect("copy");
    assert_eq!(totals.a_to_b, 5000);
    assert_eq!(totals.b_to_a, 300);
    assert_eq!(meter.read_bytes(), totals.a_to_b);
    assert_eq!(meter.write_bytes(), totals.b_to_a);
}

#[tokio::test]
async fn the_handshake_histogram_is_exported_with_adr_029_buckets() {
    let router = SniRouter::empty(SniAction::Passthrough(
        PassthroughConfig::new("127.0.0.1:9").expect("valid upstream"),
    ));
    let metrics = L4Metrics::new(MetricsRegistry::new());
    let route = router.lookup(Some("whatever.example"));
    metrics.observe_handshake(&route, 0.012).expect("observe");
    let rendered = metrics.registry().render();
    assert!(rendered.contains(&format!("# TYPE {HANDSHAKE_DURATION_SECONDS} histogram")));
    assert!(rendered.contains(&format!(
        "{HANDSHAKE_DURATION_SECONDS}_bucket{{sni=\"_other\",le=\"0.025\"}} 1"
    )));
}
