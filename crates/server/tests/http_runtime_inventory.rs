//! Real-server tests for the caddy-rs `GET /runtime/inventory` admin extension (T-ADMIN-023).
//!
//! Caddy v2.11.7 has no general runtime-inventory endpoint (`external/caddy/admin.go` registers
//! only `/config/`, `/id/`, `/stop`, `/debug/*` plus module-owned routes), so this is a documented
//! caddy-rs extension (DIV-0018). The server runtime installs a snapshot after each successful
//! apply; these tests drive the real admin listener and assert generation/listener/certificate
//! inventory, reload freshness, failed-apply honesty and read-only behaviour.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_test_support::free_port;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LOADED_CERT: &str = include_str!("../../tls/testdata/acme/localhost-cert.pem");
const LOADED_KEY: &str = include_str!("../../tls/testdata/acme/localhost-key.pem");

fn inventory_config(admin_port: u16, listen: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"listen": format!("127.0.0.1:{admin_port}")},
        "apps": {
            "http": {"servers": {"srv0": {
                "listen": [listen],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}},
            "tls": {"certificates": {"load_pem": [{
                "certificate": LOADED_CERT,
                "key": LOADED_KEY
            }]}}
        }
    }))
    .expect("inventory config decodes")
}

fn proxy_health_config(admin_port: u16, listen: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"listen": format!("127.0.0.1:{admin_port}")},
        "apps": {"http": {"servers": {"srv0": {
            "listen": [listen],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "127.0.0.1:9"}],
                "health_checks": {"active": {"uri": "/health", "interval": "1s"}}
            }]}]
        }}}}
    }))
    .expect("proxy health config decodes")
}

async fn admin_request(address: SocketAddr, method: &str, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(address).await.expect("admin connect");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("admin response timeout")
        .expect("read admin response");
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed admin response: {text:?}"));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed status line: {head:?}"));
    let value = serde_json::from_str(body).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn runtime_inventory_lists_generation_listeners_and_loaded_certificates() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    // An ephemeral admin listener avoids a fixed-port race for this single-apply test.
    store
        .load(inventory_config(0, "127.0.0.1:0"))
        .expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let admin = runtime.admin_address().expect("admin listener bound");

    let (status, value) = admin_request(admin, "GET", "/runtime/inventory").await;
    assert_eq!(status, 200, "{value}");
    assert!(
        value["extension"]
            .as_str()
            .expect("extension marker")
            .contains("DIV-0018"),
        "{value}"
    );
    assert_eq!(value["generation"]["id"], 1);
    assert_eq!(value["generation"]["state"], "active");
    assert_eq!(value["snapshot"]["available"], true);
    assert_eq!(value["snapshot"]["generation_id"], 1);
    assert_eq!(value["snapshot"]["stale"], false);
    assert!(value["admin"]["bound"].as_str().is_some(), "{value}");
    let listeners = value["listeners"].as_array().expect("listeners");
    assert_eq!(listeners.len(), 1, "{value}");
    assert_eq!(listeners[0]["server"], "srv0");
    assert_eq!(listeners[0]["configured"], "127.0.0.1:0");
    assert!(
        listeners[0]["bound"]
            .as_str()
            .is_some_and(|bound| bound.contains("127.0.0.1:")),
        "listener must report its bound address: {value}"
    );
    assert_eq!(listeners[0]["tls"], false);
    let certificates = value["certificates"].as_array().expect("certificates");
    assert!(
        certificates
            .iter()
            .any(|certificate| certificate["source"] == "loaded"),
        "manually loaded apps.tls certificate must be inventoried: {value}"
    );
    let loaded = certificates
        .iter()
        .find(|certificate| certificate["source"] == "loaded")
        .expect("loaded certificate");
    assert!(
        !loaded["subject"].as_str().unwrap_or("").is_empty(),
        "{loaded}"
    );
    assert!(loaded["not_after"].as_f64().is_some(), "{loaded}");
    assert!(
        loaded["sans"]
            .as_array()
            .is_some_and(|sans| !sans.is_empty()),
        "{loaded}"
    );
    assert_eq!(value["upstreams"], serde_json::json!([]));
    assert_eq!(value["health_checks"], serde_json::json!([]));

    // Read-only extension.
    let (status, _) = admin_request(admin, "POST", "/runtime/inventory").await;
    assert_eq!(status, 405);
    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_inventory_tracks_reload_and_health_check_schedulers() {
    let admin_port = free_port();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(proxy_health_config(admin_port, "127.0.0.1:0"))
        .expect("proxy health config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let admin: SocketAddr = format!("127.0.0.1:{admin_port}")
        .parse()
        .expect("admin address");

    let (_, value) = admin_request(admin, "GET", "/runtime/inventory").await;
    let health_checks = value["health_checks"].as_array().expect("health_checks");
    assert_eq!(health_checks.len(), 1, "{value}");
    assert_eq!(health_checks[0]["generation"], 1);
    assert_eq!(health_checks[0]["checkers"], 1);
    let old_hash = value["generation"]["config_hash"]
        .as_str()
        .expect("config hash")
        .to_string();

    // Reload with a different concrete listener port: generation/config hash/listener inventory
    // must all move together in the installed snapshot.
    let new_port = free_port();
    store
        .load(proxy_health_config(
            admin_port,
            &format!("127.0.0.1:{new_port}"),
        ))
        .expect("reload validates");
    runtime.apply().await.expect("reload applies");
    let (_, value) = admin_request(admin, "GET", "/runtime/inventory").await;
    assert_eq!(value["generation"]["id"], 2);
    assert_eq!(value["snapshot"]["generation_id"], 2);
    assert_eq!(value["snapshot"]["stale"], false);
    let new_hash = value["generation"]["config_hash"]
        .as_str()
        .expect("config hash");
    assert_ne!(new_hash, old_hash, "config hash must change on reload");
    let listeners = value["listeners"].as_array().expect("listeners");
    assert_eq!(listeners.len(), 1, "{value}");
    assert_eq!(listeners[0]["configured"], format!("127.0.0.1:{new_port}"));
    let health_checks = value["health_checks"].as_array().expect("health_checks");
    assert_eq!(health_checks[0]["generation"], 2);

    // A failed apply must leave the previous generation's snapshot/inventory intact.
    let broken = Config::from_value(serde_json::json!({
        "admin": {"listen": format!("127.0.0.1:{admin_port}")},
        "apps": {"http": {"http_port": 0, "servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "static_response", "body": "broken"}]}]
        }}}}
    }))
    .expect("broken config decodes");
    store.load(broken).expect("broken config validates");
    assert!(
        runtime.apply().await.is_err(),
        "TLS without certificates must fail"
    );
    let (_, value) = admin_request(admin, "GET", "/runtime/inventory").await;
    // The failed config is now the store's active generation, but the runtime is still serving the
    // last successfully applied one; the endpoint must represent that divergence explicitly rather
    // than presenting the snapshot as current.
    assert_eq!(value["generation"]["id"], 3);
    assert_eq!(value["runtime"]["applied_generation_id"], 2);
    assert_eq!(value["runtime"]["in_sync"], false);
    assert_eq!(value["snapshot"]["generation_id"], 2);
    assert_eq!(value["snapshot"]["stale"], true);
    assert!(
        value["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap_or("").contains("apply failed")),
        "{value}"
    );
    let listeners = value["listeners"].as_array().expect("listeners");
    assert_eq!(
        listeners[0]["configured"],
        format!("127.0.0.1:{new_port}"),
        "listener inventory keeps the last applied snapshot: {value}"
    );
    runtime.shutdown().await;
}
