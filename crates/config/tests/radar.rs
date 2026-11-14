//! caddy-rs extension config surface: the global `radar { ... }` option (ADR-0020) and the
//! per-server `trust_cdn` option (ADR-013), tracked by T-CONF-079.
//!
//! These tests pin the adapter output only. Runtime enablement (Radar client, matchers, handlers,
//! and resolving a `trust_cdn` profile into `trusted_proxies`) belongs to the runtime rows
//! (T-ROUTE-059/T-ROUTE-060), and `Config` validation of the emitted extension keys is part of that
//! work: the adapter deliberately carries the configuration without extending the core model.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// Adapt a Caddyfile that configures a global block plus one HTTP server.
fn adapt_with_global(global: &str) -> Value {
    let caddyfile = format!("{{\n{global}}}\n\n:8080 {{\n\trespond \"ok\"\n}}\n");
    adapt(&caddyfile)
        .unwrap_or_else(|error| panic!("{global:?}: {error}"))
        .config
}

/// Adapt a Caddyfile and return the emitted `radar` object.
fn adapted_radar(radar_block: &str) -> Value {
    let config = adapt_with_global(radar_block);
    config
        .get("radar")
        .cloned()
        .unwrap_or_else(|| panic!("no `radar` in {config}"))
}

/// Adapt a Caddyfile and return the located error message.
fn adapt_error(caddyfile: &str) -> String {
    match adapt(caddyfile) {
        Ok(adapted) => panic!("expected an error, got {}", adapted.config),
        Err(error) => error.to_string(),
    }
}

/// Assert the message is located (carries a `Caddyfile:line:column` label) and mentions `needle`.
fn assert_located(message: &str, needle: &str) {
    assert!(
        message.contains("Caddyfile line "),
        "error is not located: {message}"
    );
    assert!(
        message.contains(needle),
        "error does not mention {needle:?}: {message}"
    );
}

/// Recursively look for an object key anywhere in the adapted JSON.
fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(key) || map.values().any(|item| contains_key(item, key))
        }
        Value::Array(items) => items.iter().any(|item| contains_key(item, key)),
        _ => false,
    }
}

#[test]
fn empty_radar_block_adapts_to_the_documented_defaults() {
    let radar = adapted_radar("\tradar {\n\t}\n");
    assert_eq!(
        radar,
        json!({
            "mode": "auto",
            "protect": true,
            "poll_interval": "60s",
            "cache_ttl": "120s",
            "storage": { "type": "file" },
            "endpoints": {
                "ddos_l7": true,
                "ddos_l34": true,
                "bgp_hijacks": true,
                "traffic_anomalies": true
            }
        })
    );
    // Optional fields are omitted until configured.
    assert!(radar.get("api_token").is_none(), "api_token: {radar}");
    assert!(radar.get("filters").is_none(), "filters: {radar}");
    assert_eq!(radar["mode"], json!("auto"));
    assert_eq!(radar["protect"], json!(true));
    assert_eq!(radar["storage"]["type"], json!("file"));
    for endpoint in ["ddos_l7", "ddos_l34", "bgp_hijacks", "traffic_anomalies"] {
        assert_eq!(radar["endpoints"][endpoint], json!(true), "{endpoint}");
    }
}

#[test]
fn every_radar_field_maps_to_the_adr_json() {
    let radar = adapted_radar(
        "\tradar {\n\
         \t\tmode on\n\
         \t\tprotect false\n\
         \t\tapi_token \"test-token\"\n\
         \t\tpoll_interval 90s\n\
         \t\tcache_ttl 5m\n\
         \t\tstorage \"file\" {\n\
         \t\t\tpath \"/var/lib/caddy-rs/radar-cache.json\"\n\
         \t\t}\n\
         \t\tendpoints {\n\
         \t\t\tddos_l7 false\n\
         \t\t\tddos_l34 true\n\
         \t\t\tbgp_hijacks false\n\
         \t\t\ttraffic_anomalies true\n\
         \t\t}\n\
         \t\tfilters {\n\
         \t\t\tmin_magnitude 1000\n\
         \t\t\tcountries [\"CN\", \"RU\"]\n\
         \t\t\tasns [12345, 67890]\n\
         \t\t}\n\
         \t}\n",
    );
    assert_eq!(radar["mode"], json!("on"));
    assert_eq!(radar["protect"], json!(false));
    assert_eq!(radar["api_token"], json!("test-token"));
    assert_eq!(radar["poll_interval"], json!("90s"));
    // `5m` is emitted in the ADR's seconds form.
    assert_eq!(radar["cache_ttl"], json!("300s"));
    assert_eq!(
        radar["storage"],
        json!({ "type": "file", "path": "/var/lib/caddy-rs/radar-cache.json" })
    );
    assert_eq!(
        radar["endpoints"],
        json!({
            "ddos_l7": false,
            "ddos_l34": true,
            "bgp_hijacks": false,
            "traffic_anomalies": true
        })
    );
    assert_eq!(
        radar["filters"],
        json!({ "min_magnitude": 1000, "countries": ["CN", "RU"], "asns": [12345, 67890] })
    );
}

#[test]
fn mode_off_and_redis_and_memory_storage_map() {
    let radar = adapted_radar(
        "\tradar {\n\
         \t\tmode off\n\
         \t\tstorage \"redis\" {\n\
         \t\t\tredis_url \"redis://localhost:6379\"\n\
         \t\t\tkey_prefix \"radar:\"\n\
         \t\t}\n\
         \t}\n",
    );
    assert_eq!(radar["mode"], json!("off"));
    assert_eq!(
        radar["storage"],
        json!({ "type": "redis", "redis_url": "redis://localhost:6379", "key_prefix": "radar:" })
    );

    let radar = adapted_radar("\tradar {\n\t\tstorage \"memory\"\n\t}\n");
    assert_eq!(radar["storage"], json!({ "type": "memory" }));
    assert_eq!(radar["mode"], json!("auto"));
}

#[test]
fn no_enabled_key_is_ever_emitted() {
    // A fully specified block must not grow an `enabled` key anywhere.
    let config = adapt_with_global(
        "\tradar {\n\
         \t\tmode auto\n\
         \t\tprotect true\n\
         \t\tstorage \"memory\"\n\
         \t}\n",
    );
    assert!(
        !contains_key(&config, "enabled"),
        "unexpected enabled: {config}"
    );
    assert!(!contains_key(&config["radar"], "enabled"));

    // The pre-ADR spelling is rejected, not ignored, so a stale `enabled` can never be adapted.
    let message =
        adapt_error("{\n\tradar {\n\t\tenabled true\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n");
    assert_located(&message, "`enabled` is not a radar option");
    assert_located(&message, "mode auto|on|off");
}

#[test]
fn poll_interval_below_the_minimum_is_a_located_error() {
    let message = adapt_error(
        "{\n\tradar {\n\t\tpoll_interval 10s\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "`poll_interval` must be at least 30s");
    assert_located(&message, "10s");

    // Exactly the minimum is accepted.
    let radar = adapted_radar("\tradar {\n\t\tpoll_interval 30s\n\t}\n");
    assert_eq!(radar["poll_interval"], json!("30s"));
}

#[test]
fn unknown_radar_sub_option_is_a_located_error() {
    let message = adapt_error(
        "{\n\tradar {\n\t\tbogus_option true\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "unknown radar option `bogus_option`");

    let message = adapt_error(
        "{\n\tradar {\n\t\tstorage \"sqlite\"\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "unknown radar storage backend `sqlite`");
}

#[test]
fn stock_compat_rejects_radar_and_trust_cdn() {
    let message =
        adapt_error("{\n\tstock_compat true\n\tradar {\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n");
    assert_located(&message, "global option `radar`");
    assert_located(&message, "caddy-rs extension, not in Caddy v2.11.9");
    assert_located(&message, "not supported by this build");

    let message = adapt_error(
        "{\n\tstock_compat true\n\ttrust_cdn cloudflare\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "global option `trust_cdn`");
    assert_located(&message, "caddy-rs extension, not in Caddy v2.11.9");

    let message = adapt_error(
        "{\n\tstock_compat true\n\tservers {\n\t\ttrust_cdn\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "`servers` option `trust_cdn`");
    assert_located(&message, "stock_compat true");
}

/// Build the config for the per-server `trust_cdn` matrix and return its servers object.
fn adapted_servers(global: &str) -> Value {
    let caddyfile = format!(
        "{{\n{global}}}\n\n\
         :443 {{\n\trespond \"ok\"\n}}\n\n\
         :8443 {{\n\trespond \"ok\"\n}}\n\n\
         :9443 {{\n\trespond \"ok\"\n}}\n"
    );
    let config = adapt(&caddyfile)
        .unwrap_or_else(|error| panic!("{global:?}: {error}"))
        .config;
    config["apps"]["http"]["servers"].clone()
}

#[test]
fn per_server_trust_cdn_wins_over_the_global_default() {
    let servers = adapted_servers(
        "\ttrust_cdn cloudflare\n\
         \tservers :443 {\n\
         \t\ttrust_cdn fastly\n\
         \t}\n\
         \tservers :8443 {\n\
         \t\ttrusted_proxies static 10.0.0.0/8\n\
         \t}\n",
    );
    let servers = servers.as_object().expect("servers object");
    let by_listen = |listen: &str| -> Value {
        servers
            .values()
            .find(|server| server["listen"] == json!([listen]))
            .unwrap_or_else(|| panic!("no server listening on {listen}: {servers:?}"))
            .clone()
    };

    // Server-level `trust_cdn` overrides the global provider.
    assert_eq!(
        by_listen(":443")["trust_cdn"],
        json!({ "provider": "fastly" })
    );
    // An explicit server-level `trusted_proxies` blocks the trust_cdn merge.
    let blocked = by_listen(":8443");
    assert_eq!(
        blocked["trusted_proxies"],
        json!({ "source": "static", "ranges": ["10.0.0.0/8"] })
    );
    assert!(
        blocked.get("trust_cdn").is_none(),
        "trust_cdn must not merge over explicit trusted_proxies: {blocked}"
    );
    // A server without its own setting inherits the global default.
    assert_eq!(
        by_listen(":9443")["trust_cdn"],
        json!({ "provider": "cloudflare" })
    );
}

#[test]
fn bare_trust_cdn_forms_emit_the_boolean_marker() {
    let config = adapt_with_global("\ttrust_cdn\n");
    assert_eq!(config["trust_cdn"], json!(true));

    let servers = adapted_servers("\tservers :443 {\n\t\ttrust_cdn\n\t}\n");
    let server = servers
        .as_object()
        .expect("servers object")
        .values()
        .find(|server| server["listen"] == json!([":443"]))
        .expect("server on :443");
    assert_eq!(server["trust_cdn"], json!(true));
    // No global default: servers that were not named keep no marker.
    let other = servers
        .as_object()
        .expect("servers object")
        .values()
        .find(|server| server["listen"] == json!([":8443"]))
        .expect("server on :8443");
    assert!(other.get("trust_cdn").is_none(), "{other}");
}

#[test]
fn trust_cdn_block_overrides_and_unknown_options() {
    let config = adapt_with_global(
        "\ttrust_cdn cloudflare {\n\
         \t\tclient_ip_header \"CF-Connecting-IP\"\n\
         \t\tipv4_cidrs 192.0.2.0/24\n\
         \t\tipv6_cidrs 2001:db8::/32\n\
         \t\tstrict false\n\
         \t}\n",
    );
    assert_eq!(
        config["trust_cdn"],
        json!({
            "provider": "cloudflare",
            "client_ip_header": "CF-Connecting-IP",
            "ipv4_cidrs": ["192.0.2.0/24"],
            "ipv6_cidrs": ["2001:db8::/32"],
            "strict": false
        })
    );

    let message = adapt_error(
        "{\n\ttrust_cdn cloudflare {\n\t\tbogus_field true\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert_located(&message, "unknown `trust_cdn` option `bogus_field`");
}
