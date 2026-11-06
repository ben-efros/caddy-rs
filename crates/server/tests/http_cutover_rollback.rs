//! Staged-cutover rollback proof (T-COMPAT-028).
//!
//! This test exercises the local cutover/rollback contract through the real server runtime and
//! real TCP listeners:
//!
//! 1. generation A serves a cleartext static response ("old");
//! 2. a *new* configuration that fails validation is rejected by `GenerationStore::load` and the
//!    running generation keeps serving;
//! 3. a new configuration that validates but fails at apply (TLS termination without
//!    certificates) leaves the running generation serving;
//! 4. loading the previous configuration again and applying it restores service ("old").
//!
//! It does not replace the external reference-deployment cutover (see
//! docs/operations/CUTOVER.md); it proves the local generation-rollback half offline.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A cleartext HTTP server: one listener on an ephemeral port serving `body`.
fn static_config(body: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
        }}}}
    }))
    .expect("static config decodes")
}

/// A configuration that validates but fails at apply: TLS termination without certificates.
fn tls_without_certificates_config() -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "static_response", "body": "new"}]}]
        }}}}
    }))
    .expect("TLS-without-certificates config decodes")
}

/// A configuration rejected by load-time validation (located error).
fn invalid_config() -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "read_timeout": "soon",
            "routes": [{"handle": [{"handler": "static_response", "body": "broken"}]}]
        }}}}
    }))
    .expect("invalid config still decodes so validation can reject it")
}

/// Raw HTTP/1.1 GET with `Connection: close`, returning the response body or panicking.
async fn get_body(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).await.expect("connect listener");
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    let response = String::from_utf8_lossy(&response);
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed HTTP response: {response:?}"));
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected a 200 response, got: {head}"
    );
    body.to_string()
}

#[tokio::test]
async fn invalid_reload_and_failed_apply_keep_old_generation_and_rollback_restores_it() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(static_config("old"))
        .expect("generation A validates and loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("generation A applies");
    let old_generation = runtime.status().generation_id.expect("A is active");
    let old_address = runtime
        .listener_address("127.0.0.1:0")
        .expect("generation A listener is bound");
    assert_eq!(get_body(old_address, "/").await, "old");

    // 1. Invalid configuration is rejected before it can replace the running generation. (Since
    //    T-HTTP-042 this is a load-time validation error with a located path.)
    let load_error = store
        .load(invalid_config())
        .expect_err("invalid config must be rejected by validation");
    assert!(
        load_error
            .to_string()
            .contains("apps.http.servers.srv0.read_timeout"),
        "validation error must name the field, got: {load_error}"
    );
    assert_eq!(
        runtime.status().generation_id,
        Some(old_generation),
        "a rejected load must not change the active runtime generation"
    );
    assert_eq!(get_body(old_address, "/").await, "old");

    // 2. A configuration that validates but fails during apply (TLS without certificates) must
    //    leave the previous generation serving; the failed generation is never activated.
    store
        .load(tls_without_certificates_config())
        .expect("failing generation validates");
    let apply_error = runtime
        .apply()
        .await
        .expect_err("TLS without certificates must fail the apply");
    assert!(
        apply_error.to_string().contains("certificate")
            || apply_error.to_string().contains("terminates TLS"),
        "apply error must name the TLS/certificate problem, got: {apply_error}"
    );
    assert_eq!(
        runtime.status().generation_id,
        Some(old_generation),
        "a failed apply must keep the previous generation active"
    );
    assert_eq!(
        get_body(old_address, "/").await,
        "old",
        "the previous generation must keep serving after a failed apply"
    );

    // 3. Rollback: load the previous configuration again and apply it. The new generation takes
    //    over and serves the old content; the old listener address is drained/replaced according
    //    to the runtime's listener lifecycle.
    store
        .load(static_config("old"))
        .expect("rollback generation validates");
    runtime.apply().await.expect("rollback generation applies");
    let rollback_generation = runtime
        .status()
        .generation_id
        .expect("rollback generation is active");
    assert_ne!(
        rollback_generation, old_generation,
        "rollback is a new generation, not a resurrection of the failed one"
    );
    let rollback_address = runtime
        .listener_address("127.0.0.1:0")
        .expect("rollback listener is bound");
    assert_eq!(
        get_body(rollback_address, "/").await,
        "old",
        "rollback must restore the previous configuration's behaviour"
    );

    runtime.shutdown().await;
}
