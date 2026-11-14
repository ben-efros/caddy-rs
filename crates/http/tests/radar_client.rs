//! Integration tests for the Radar client: modes, routability gate, polling, parsing, TTL/stale
//! behaviour, filters, persistence (file/memory/Redis) and metrics.
//!
//! No test reaches the Internet: the client is driven through a stub [`RadarTransport`], except for
//! the polling-loop test, which talks to a local `tokio::net::TcpListener` speaking HTTP/1.1.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use caddy_rs_http::radar_store::MAX_RADAR_BYTES;
use caddy_rs_http::{
    FileStorage, HyperRadarTransport, MemoryStorage, RadarClient, RadarConfig, RadarEndpoint,
    RadarFilters, RadarLog, RadarMode, RadarStorage, RadarTransport, RedisStorage, StorageSpec,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Records every `get` and answers from a per-endpoint body table (or fails on demand).
#[derive(Debug)]
struct StubTransport {
    requests: Mutex<Vec<(String, Option<String>)>>,
    bodies: Mutex<BTreeMap<&'static str, Vec<u8>>>,
    fail: AtomicBool,
}

impl StubTransport {
    fn sample() -> Arc<Self> {
        let transport = Self {
            requests: Mutex::new(Vec::new()),
            bodies: Mutex::new(BTreeMap::new()),
            fail: AtomicBool::new(false),
        };
        for endpoint in RadarEndpoint::ALL {
            transport.set_body(endpoint, sample_body(endpoint));
        }
        Arc::new(transport)
    }

    fn set_body(&self, endpoint: RadarEndpoint, body: &str) {
        self.bodies
            .lock()
            .unwrap()
            .insert(endpoint.path(), body.as_bytes().to_vec());
    }

    fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|(url, _)| url.clone())
            .collect()
    }
}

#[async_trait]
impl RadarTransport for StubTransport {
    async fn get(&self, url: &str, token: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        self.requests
            .lock()
            .unwrap()
            .push((url.to_string(), token.map(str::to_string)));
        if self.fail.load(Ordering::SeqCst) {
            return Err("stub transport: forced failure".to_string());
        }
        let endpoint = RadarEndpoint::ALL
            .into_iter()
            .find(|endpoint| url.ends_with(endpoint.path()));
        match endpoint {
            Some(endpoint) => {
                let body = self
                    .bodies
                    .lock()
                    .unwrap()
                    .get(endpoint.path())
                    .cloned()
                    .unwrap_or_default();
                Ok((200, body))
            }
            None => Ok((404, b"{}".to_vec())),
        }
    }
}

/// Captured log lines, so the exact mode/enable strings can be asserted.
#[derive(Debug, Default)]
struct CapturedLog {
    lines: Mutex<Vec<String>>,
}

impl CapturedLog {
    fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    fn count(&self, needle: &str) -> usize {
        self.lines()
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }

    fn has_line(&self, expected: &str) -> bool {
        self.lines().iter().any(|line| line == expected)
    }
}

impl RadarLog for CapturedLog {
    fn info(&self, line: &str) {
        self.lines.lock().unwrap().push(line.to_string());
    }
}

struct Harness {
    client: RadarClient,
    transport: Arc<StubTransport>,
    storage: Arc<dyn RadarStorage>,
    log: Arc<CapturedLog>,
}

fn harness(config: RadarConfig) -> Harness {
    harness_with(config, Arc::new(MemoryStorage::new()))
}

fn harness_with(config: RadarConfig, storage: Arc<dyn RadarStorage>) -> Harness {
    let transport = StubTransport::sample();
    let log = Arc::new(CapturedLog::default());
    let client = RadarClient::new(config, transport.clone(), storage.clone(), log.clone());
    Harness {
        client,
        transport,
        storage,
        log,
    }
}

fn memory_config() -> RadarConfig {
    RadarConfig {
        storage: StorageSpec::Memory,
        ..RadarConfig::default()
    }
}

/// Poll until `condition` holds (max 5 s), so tests do not depend on scheduler timing.
async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not satisfied within 5s");
}

fn sample_body(endpoint: RadarEndpoint) -> &'static str {
    match endpoint {
        RadarEndpoint::DdosL7 => {
            r#"{"success":true,"result":{"top":[
                {"asn":64500,"country":"DE","magnitude":12.5,"kind":"volumetric","timestamp":"2025-01-01T00:00:00Z","extra":{"x":1}},
                {"asn":64501,"country":"US","magnitude":3.0,"kind":"dns","timestamp":"2025-01-01T00:01:00Z"}
            ]}}"#
        }
        RadarEndpoint::DdosL34 => {
            r#"{"success":true,"result":[
                {"asn":"AS64502","country":"FR","value":42.0,"type":"syn-flood","timestamp":1735689600}
            ]}"#
        }
        RadarEndpoint::BgpHijacks => {
            r#"{"success":true,"result":{"hijacks":[
                {"origin":{"asn":64503,"country":"NL"},"magnitude":7.25,"kind":"hijack","start":"2025-01-02T00:00:00Z"}
            ]}}"#
        }
        RadarEndpoint::TrafficAnomalies => {
            r#"{"success":true,"result":{"anomalies":[
                {"asn":64504,"country":"JP","score":55.5,"anomaly_type":"traffic-drop","date":"2025-01-03"}
            ]}}"#
        }
    }
}

#[tokio::test]
async fn auto_mode_is_idle_until_a_routable_ip_and_then_enables_once() {
    let harness = harness(RadarConfig {
        mode: RadarMode::Auto,
        ..memory_config()
    });
    harness.client.start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(harness.transport.request_count(), 0);
    assert_eq!(harness.client.metrics().radar_storage_reads_total(), 0);
    assert!(!harness.client.is_enabled());
    assert!(harness
        .log
        .has_line("radar: mode=auto (waiting for Internet-routable client IP)"));
    assert_eq!(harness.log.count("radar: enabling"), 0);

    // Private and loopback addresses never enable radar.
    assert!(
        !harness
            .client
            .on_client_ip("10.0.0.5".parse().unwrap(), Some(64500))
            .await
    );
    assert!(
        !harness
            .client
            .on_client_ip("192.168.1.10".parse().unwrap(), None)
            .await
    );
    assert!(
        !harness
            .client
            .on_client_ip("::1".parse().unwrap(), None)
            .await
    );
    assert_eq!(harness.transport.request_count(), 0);
    assert!(!harness.client.is_enabled());

    // The first routable IP enables radar and starts polling.
    assert!(
        harness
            .client
            .on_client_ip("203.0.113.5".parse().unwrap(), Some(64500))
            .await
    );
    assert!(harness
        .log
        .has_line("radar: enabling (Internet-routable IP detected: 203.0.113.5, ASN 64500)"));
    assert_eq!(harness.client.metrics().radar_auto_enables_total(), 1);
    assert!(harness.client.is_enabled());
    wait_until(|| harness.transport.request_count() >= 4).await;
    wait_until(|| harness.client.metrics().radar_entries_cached() == 5).await;

    // Idempotent: later routable IPs do nothing.
    assert!(
        !harness
            .client
            .on_client_ip("8.8.8.8".parse().unwrap(), Some(13335))
            .await
    );
    assert_eq!(harness.client.metrics().radar_auto_enables_total(), 1);
    assert_eq!(harness.log.count("radar: enabling"), 1);
    harness.client.shutdown();
}

#[tokio::test]
async fn auto_mode_omits_the_asn_suffix_when_unknown() {
    let harness = harness(RadarConfig {
        mode: RadarMode::Auto,
        ..memory_config()
    });
    harness.client.start().await;
    assert!(
        harness
            .client
            .on_client_ip("198.51.100.7".parse().unwrap(), None)
            .await
    );
    assert!(harness
        .log
        .has_line("radar: enabling (Internet-routable IP detected: 198.51.100.7)"));
    assert_eq!(harness.log.count("ASN"), 0);
    harness.client.shutdown();
}

#[tokio::test]
async fn on_mode_polls_immediately_and_off_mode_does_nothing() {
    let on = harness(RadarConfig {
        mode: RadarMode::On,
        ..memory_config()
    });
    on.client.start().await;
    assert!(on.log.has_line("radar: mode=on (polling started)"));
    wait_until(|| on.transport.request_count() >= 4).await;
    wait_until(|| on.client.metrics().radar_entries_cached() == 5).await;
    assert!(on.client.is_enabled());
    let paths = on.transport.paths();
    for endpoint in RadarEndpoint::ALL {
        assert!(
            paths.iter().any(|url| url.ends_with(endpoint.path())),
            "missing poll for {}",
            endpoint.path()
        );
    }
    on.client.shutdown();

    let off = harness(RadarConfig {
        mode: RadarMode::Off,
        ..memory_config()
    });
    off.client.start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(off.transport.request_count(), 0);
    assert!(off.log.lines().is_empty());
    assert!(!off.client.is_enabled());
    assert_eq!(off.client.metrics().radar_entries_cached(), 0);
    assert_eq!(off.client.metrics().radar_storage_reads_total(), 0);
    assert!(
        !off.client
            .on_client_ip("203.0.113.5".parse().unwrap(), None)
            .await
    );
    assert_eq!(off.transport.request_count(), 0);
}

#[tokio::test]
async fn polling_parses_all_four_endpoints_into_structured_entries() {
    let harness = harness(memory_config());
    let outcome = harness.client.poll_once().await;
    assert_eq!(outcome.endpoints_ok, 4);
    assert_eq!(outcome.endpoints_failed, 0);
    assert_eq!(outcome.entries, 5);
    assert_eq!(harness.client.metrics().radar_polls_total(), 1);
    assert_eq!(harness.client.metrics().radar_entries_cached(), 5);

    let l7 = harness
        .client
        .cached_entries(RadarEndpoint::DdosL7)
        .await
        .expect("l7 cache");
    assert_eq!(l7.len(), 2);
    assert_eq!(l7[0].asn, Some(64500));
    assert_eq!(l7[0].country.as_deref(), Some("DE"));
    assert_eq!(l7[0].magnitude, Some(12.5));
    assert_eq!(l7[0].kind.as_deref(), Some("volumetric"));
    assert_eq!(l7[0].timestamp.as_deref(), Some("2025-01-01T00:00:00Z"));
    assert_eq!(l7[1].asn, Some(64501));

    let l34 = harness
        .client
        .cached_entries(RadarEndpoint::DdosL34)
        .await
        .expect("l34 cache");
    assert_eq!(l34.len(), 1);
    assert_eq!(l34[0].asn, Some(64502), "AS-prefixed ASN parses");
    assert_eq!(l34[0].magnitude, Some(42.0));
    assert_eq!(l34[0].timestamp.as_deref(), Some("1735689600"));

    let bgp = harness
        .client
        .cached_entries(RadarEndpoint::BgpHijacks)
        .await
        .expect("bgp cache");
    assert_eq!(bgp[0].asn, Some(64503));
    assert_eq!(bgp[0].country.as_deref(), Some("NL"));
    assert_eq!(bgp[0].kind.as_deref(), Some("hijack"));

    let anomalies = harness
        .client
        .cached_entries(RadarEndpoint::TrafficAnomalies)
        .await
        .expect("anomaly cache");
    assert_eq!(anomalies[0].asn, Some(64504));
    assert_eq!(anomalies[0].magnitude, Some(55.5));
    assert_eq!(anomalies[0].kind.as_deref(), Some("traffic-drop"));

    // The token is only sent when configured; none is configured here.
    assert!(harness
        .transport
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|(_, token)| token.is_none()));
}

#[tokio::test]
async fn cache_ttl_controls_refetch_and_failures_serve_stale() {
    let harness = harness(RadarConfig {
        cache_ttl: Duration::from_millis(40),
        ..memory_config()
    });
    let first = harness.client.poll_once().await;
    assert_eq!(first.entries, 5);
    assert_eq!(harness.transport.request_count(), 4);

    // Fresh cache: a second cycle does not refetch.
    let cached = harness.client.poll_once().await;
    assert_eq!(cached.entries, 5);
    assert_eq!(cached.endpoints_ok, 4);
    assert_eq!(harness.transport.request_count(), 4);

    // TTL expiry refetches.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let refreshed = harness.client.poll_once().await;
    assert_eq!(refreshed.entries, 5);
    assert_eq!(harness.transport.request_count(), 8);

    // Forced failure after expiry: the previous entries are still served (never fail closed).
    harness.transport.set_fail(true);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let stale = harness.client.poll_once().await;
    assert_eq!(stale.endpoints_failed, 4);
    assert_eq!(stale.stale_serves, 4);
    assert_eq!(stale.entries, 5);
    assert_eq!(harness.client.metrics().radar_stale_serves_total(), 4);
    assert_eq!(harness.client.metrics().radar_errors_total(), 4);
    assert_eq!(harness.client.metrics().radar_entries_cached(), 5);
    assert_eq!(
        harness
            .client
            .cached_entries(RadarEndpoint::DdosL7)
            .await
            .expect("stale l7")
            .len(),
        2
    );
    assert!(harness.log.count("serving stale") == 4);
}

#[tokio::test]
async fn filters_reduce_the_cached_entries() {
    // min_magnitude keeps 12.5, 42.0 and 55.5; drops 3.0 and 7.25.
    let magnitude = harness(RadarConfig {
        filters: RadarFilters {
            min_magnitude: Some(10.0),
            ..RadarFilters::default()
        },
        ..memory_config()
    });
    assert_eq!(magnitude.client.poll_once().await.entries, 3);

    // Country allowlist keeps DE and FR only.
    let countries = harness(RadarConfig {
        filters: RadarFilters {
            countries: vec!["DE".to_string(), "FR".to_string()],
            ..RadarFilters::default()
        },
        ..memory_config()
    });
    assert_eq!(countries.client.poll_once().await.entries, 2);

    // ASN allowlist keeps 64501 and 64503 only.
    let asns = harness(RadarConfig {
        filters: RadarFilters {
            asns: vec![64501, 64503],
            ..RadarFilters::default()
        },
        ..memory_config()
    });
    assert_eq!(asns.client.poll_once().await.entries, 2);
    assert_eq!(
        asns.client
            .cached_entries(RadarEndpoint::DdosL34)
            .await
            .expect("l34 cached (filtered)")
            .len(),
        0
    );
}

#[tokio::test]
async fn memory_storage_round_trips() {
    let storage = MemoryStorage::new();
    assert_eq!(storage.load("ddos/l7").await.unwrap(), None);
    storage.save("ddos/l7", "{\"entries\":[]}").await.unwrap();
    assert_eq!(
        storage.load("ddos/l7").await.unwrap().as_deref(),
        Some("{\"entries\":[]}")
    );
    assert!(!storage.is_empty().await);
}

#[tokio::test]
async fn file_storage_round_trips_atomically_and_loads_on_enable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("state/radar-cache.json");
    let storage = Arc::new(FileStorage::new(path.clone()));
    let file_config = || RadarConfig {
        mode: RadarMode::On,
        storage: StorageSpec::File { path: path.clone() },
        ..RadarConfig::default()
    };

    let first = harness_with(file_config(), storage.clone());
    first.client.start().await;
    wait_until(|| first.client.metrics().radar_storage_writes_total() == 4).await;
    assert_eq!(first.client.metrics().radar_entries_cached(), 5);
    assert!(
        path.exists(),
        "cache file must exist after a successful poll"
    );

    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read cache")).expect("JSON cache");
    let object = document.as_object().expect("cache object");
    assert_eq!(object.len(), 4);
    assert!(object.contains_key("ddos/l7"));
    assert!(object.contains_key("traffic/anomalies"));
    let temporary: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .expect("read state dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(
        temporary.is_empty(),
        "temp files left behind: {temporary:?}"
    );
    first.client.shutdown();
    drop(first);

    // `on` mode: the persisted cache is loaded at startup and a fresh cache is not refetched.
    let second = harness_with(file_config(), storage.clone());
    second.client.start().await;
    wait_until(|| second.client.metrics().radar_storage_reads_total() == 4).await;
    assert_eq!(second.client.metrics().radar_entries_cached(), 5);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(second.transport.request_count(), 0);
    second.client.shutdown();
    drop(second);

    // `auto` mode: the persisted cache is loaded when a routable IP enables radar.
    let third = harness_with(
        RadarConfig {
            mode: RadarMode::Auto,
            storage: StorageSpec::File { path: path.clone() },
            ..RadarConfig::default()
        },
        storage,
    );
    third.client.start().await;
    assert_eq!(third.client.metrics().radar_storage_reads_total(), 0);
    assert!(
        third
            .client
            .on_client_ip("203.0.113.9".parse().unwrap(), None)
            .await
    );
    wait_until(|| third.client.metrics().radar_storage_reads_total() == 4).await;
    assert_eq!(third.client.metrics().radar_entries_cached(), 5);
    assert_eq!(third.client.metrics().radar_auto_enables_total(), 1);
    assert_eq!(
        third
            .client
            .cached_entries(RadarEndpoint::BgpHijacks)
            .await
            .expect("persisted bgp entries")
            .len(),
        1
    );
    third.client.shutdown();
}

#[tokio::test]
async fn redis_storage_round_trips_against_a_resp_stub() {
    let (address, keys) = spawn_redis_stub().await;
    let storage = RedisStorage::new(format!("redis://{address}"), "radar:").expect("redis storage");
    assert_eq!(storage.load("ddos/l7").await.unwrap(), None);
    storage
        .save("ddos/l7", "{\"fetched_at_ms\":1,\"entries\":[]}")
        .await
        .expect("redis SET");
    assert_eq!(
        storage.load("ddos/l7").await.unwrap().as_deref(),
        Some("{\"fetched_at_ms\":1,\"entries\":[]}")
    );
    assert!(keys.lock().unwrap().contains_key("radar:ddos/l7"));
    // A second key proves the prefix is applied per endpoint.
    storage.save("bgp/hijacks", "{}").await.expect("redis SET");
    assert!(keys.lock().unwrap().contains_key("radar:bgp/hijacks"));
    assert_eq!(keys.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn redis_storage_failures_are_values_not_panics() {
    // Nothing is listening on the discarded port: the error must be a StorageError.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    drop(listener);
    let storage = RedisStorage::new(format!("redis://{address}"), "radar:").expect("storage");
    let error = storage
        .save("ddos/l7", "{}")
        .await
        .expect_err("closed port");
    assert!(error.to_string().contains("redis"), "{error}");
}

#[tokio::test]
async fn metric_counters_track_polls_entries_and_storage() {
    let harness = harness(memory_config());
    harness.client.poll_once().await;
    harness.client.poll_once().await;
    let snapshot = harness.client.metrics().snapshot();
    assert_eq!(snapshot.radar_polls_total, 2);
    assert_eq!(snapshot.radar_entries_cached, 5);
    assert_eq!(snapshot.radar_storage_writes_total, 4);
    assert_eq!(snapshot.radar_storage_reads_total, 0);
    assert_eq!(snapshot.radar_errors_total, 0);
    assert_eq!(snapshot.radar_stale_serves_total, 0);
    assert_eq!(snapshot.radar_auto_enables_total, 0);
    assert_eq!(harness.transport.request_count(), 4);
    // The harness storage really holds the persisted documents.
    assert!(harness.storage.load("ddos/l7").await.unwrap().is_some());
}

#[tokio::test]
async fn polling_loop_uses_http_and_sends_the_bearer_token() {
    let body = sample_body(RadarEndpoint::DdosL7);
    let (address, hits, heads) = spawn_http_stub(body).await;
    let client = RadarClient::new(
        RadarConfig {
            mode: RadarMode::On,
            base_url: format!("http://{address}/radar"),
            api_token: Some("secret-token".to_string()),
            storage: StorageSpec::Memory,
            ..RadarConfig::default()
        },
        Arc::new(HyperRadarTransport),
        Arc::new(MemoryStorage::new()),
        Arc::new(CapturedLog::default()),
    );
    client.start().await;
    wait_until(|| hits.load(Ordering::SeqCst) >= 4).await;
    wait_until(|| client.metrics().radar_entries_cached() == 8).await;

    let heads = heads.lock().unwrap().clone();
    assert!(heads
        .iter()
        .any(|head| head.contains("GET /radar/ddos/l7 HTTP/1.1")));
    assert!(heads.iter().all(|head| head
        .to_ascii_lowercase()
        .contains("authorization: bearer secret-token")));
    assert_eq!(
        client
            .cached_entries(RadarEndpoint::DdosL34)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(client.metrics().radar_polls_total() >= 1);
    client.shutdown();
}

/// Minimal HTTP/1.1 stub: accept, record the request head, reply with `body` and close.
async fn spawn_http_stub(
    body: &'static str,
) -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind http stub");
    let address = listener.local_addr().expect("stub addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let hits_task = Arc::clone(&hits);
    let heads_task = Arc::clone(&heads);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits_task);
            let heads = Arc::clone(&heads_task);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).into_owned();
                hits.fetch_add(1, Ordering::SeqCst);
                heads.lock().unwrap().push(head);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });
    (address, hits, heads)
}

/// Minimal RESP stub: `SET`/`GET` against an in-process map, one command per connection.
async fn spawn_redis_stub() -> (SocketAddr, Arc<Mutex<BTreeMap<String, String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redis stub");
    let address = listener.local_addr().expect("redis stub addr");
    let keys = Arc::new(Mutex::new(BTreeMap::new()));
    let keys_task = Arc::clone(&keys);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let keys = Arc::clone(&keys_task);
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let Ok(arguments) = read_resp_command(&mut reader).await else {
                    return;
                };
                let reply = match arguments.first().map(String::as_str) {
                    Some("SET") if arguments.len() == 3 => {
                        keys.lock()
                            .unwrap()
                            .insert(arguments[1].clone(), arguments[2].clone());
                        "+OK\r\n".to_string()
                    }
                    Some("GET") if arguments.len() == 2 => {
                        match keys.lock().unwrap().get(&arguments[1]).cloned() {
                            Some(value) => format!("${}\r\n{value}\r\n", value.len()),
                            None => "$-1\r\n".to_string(),
                        }
                    }
                    _ => "-ERR unsupported command\r\n".to_string(),
                };
                let mut stream = reader.into_inner();
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });
    (address, keys)
}

async fn read_resp_command(reader: &mut BufReader<TcpStream>) -> std::io::Result<Vec<String>> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let count: usize = line
        .trim_end_matches(['\r', '\n'])
        .strip_prefix('*')
        .and_then(|count| count.parse().ok())
        .unwrap_or(0);
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        let length: usize = header
            .trim_end_matches(['\r', '\n'])
            .strip_prefix('$')
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        let mut buffer = vec![0u8; length + 2];
        reader.read_exact(&mut buffer).await?;
        arguments.push(String::from_utf8_lossy(&buffer[..length]).into_owned());
    }
    Ok(arguments)
}

/// HTTP/1.1 stub whose body is one byte over the accepted cap.
async fn spawn_oversized_http_stub() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized http stub");
    let address = listener.local_addr().expect("stub addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits_task);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                hits.fetch_add(1, Ordering::SeqCst);
                let body = vec![b'x'; MAX_RADAR_BYTES + 1];
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                // The client rejects the body at the cap and closes: a short write here is expected.
                let _ = stream.write_all(&body).await;
                let _ = stream.flush().await;
            });
        }
    });
    (address, hits)
}

/// RESP stub that advertises a bulk reply over the cap and then sends no payload, so a client that
/// allocated and read the advertised length would hang instead of returning an error.
async fn spawn_oversized_bulk_redis_stub() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oversized redis stub");
    let address = listener.local_addr().expect("redis stub addr");
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let mut reader = BufReader::new(stream);
        if read_resp_command(&mut reader).await.is_err() {
            return;
        }
        let mut stream = reader.into_inner();
        let _ = stream
            .write_all(format!("${}\r\n", MAX_RADAR_BYTES + 1).as_bytes())
            .await;
        let _ = stream.flush().await;
    });
    address
}

#[tokio::test]
async fn http_transport_refuses_a_body_over_the_size_cap() {
    let (address, hits) = spawn_oversized_http_stub().await;
    let transport = HyperRadarTransport;
    let error = transport
        .get(&format!("http://{address}/radar/ddos/l7"), None)
        .await
        .expect_err("oversized response body must be rejected");
    assert!(error.contains("exceeds"), "{error}");
    assert!(error.contains(&MAX_RADAR_BYTES.to_string()), "{error}");
    assert!(error.contains(&address.to_string()), "{error}");
    wait_until(|| hits.load(Ordering::SeqCst) >= 1).await;
}

#[tokio::test]
async fn redis_storage_refuses_a_bulk_reply_over_the_size_cap() {
    let address = spawn_oversized_bulk_redis_stub().await;
    let storage = RedisStorage::new(format!("redis://{address}"), "radar:").expect("redis storage");
    let error = storage
        .load("ddos/l7")
        .await
        .expect_err("oversized redis bulk reply must be rejected");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(
        error.to_string().contains(&MAX_RADAR_BYTES.to_string()),
        "{error}"
    );
}
