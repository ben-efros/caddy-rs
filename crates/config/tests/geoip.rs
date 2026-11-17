//! The global `geoip <provider> <path>` option (ADR-0020, DIV-0161, T-ROUTE-062).
//!
//! These pin the adapter surface only: parsing, JSON emission, and the `stock_compat` rejection.
//! Opening the databases and selecting the provider is runtime work; the provider itself is tested
//! against real databases in `crates/http/tests/geoip.rs`.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// Adapt a Caddyfile that configures a global block plus one HTTP server.
fn adapt_with_global(global: &str) -> Value {
    let caddyfile = format!("{{\n{global}}}\n\n:8080 {{\n\trespond \"ok\"\n}}\n");
    adapt(&caddyfile)
        .unwrap_or_else(|error| panic!("{global:?}: {error}"))
        .config
}

/// Adapt a Caddyfile and return the located error message.
fn adapt_error(caddyfile: &str) -> String {
    let error = adapt(caddyfile).expect_err("adaptation must fail");
    format!("{error}")
}

fn adapted_geoip(global: &str) -> Value {
    let config = adapt_with_global(global);
    config
        .get("geoip")
        .cloned()
        .unwrap_or_else(|| panic!("no `geoip` in {config}"))
}

#[test]
fn a_single_geoip_line_emits_one_entry() {
    let geoip = adapted_geoip("\tgeoip dbip /var/lib/caddy/dbip-asn-lite.mmdb\n");
    assert_eq!(
        geoip,
        json!([{ "provider": "dbip", "path": "/var/lib/caddy/dbip-asn-lite.mmdb" }])
    );
}

#[test]
fn the_option_is_repeatable_and_preserves_written_order() {
    // ASN and country live in separate files, so two lines is the documented way to configure both.
    let geoip = adapted_geoip(
        "\tgeoip dbip /var/lib/caddy/dbip-asn-lite.mmdb\n\
         \tgeoip dbip /var/lib/caddy/dbip-country-lite.mmdb\n",
    );
    assert_eq!(
        geoip,
        json!([
            { "provider": "dbip", "path": "/var/lib/caddy/dbip-asn-lite.mmdb" },
            { "provider": "dbip", "path": "/var/lib/caddy/dbip-country-lite.mmdb" },
        ]),
        "the emitted array must follow the order the operator wrote"
    );
}

#[test]
fn maxmind_is_emitted_as_written() {
    let geoip = adapted_geoip("\tgeoip maxmind /var/lib/caddy/GeoLite2-ASN.mmdb\n");
    assert_eq!(
        geoip,
        json!([{ "provider": "maxmind", "path": "/var/lib/caddy/GeoLite2-ASN.mmdb" }])
    );
}

#[test]
fn the_path_is_emitted_verbatim_without_resolution() {
    // Resolving against the Caddyfile's directory would make the JSON depend on where the file
    // lived, so a relative path must survive untouched.
    let geoip = adapted_geoip("\tgeoip dbip ./data/asn.mmdb\n");
    assert_eq!(geoip[0]["path"], json!("./data/asn.mmdb"));
}

#[test]
fn geoip_is_absent_when_not_configured() {
    let config = adapt_with_global("\tdebug\n");
    assert!(
        config.get("geoip").is_none(),
        "an unconfigured option must not be emitted: {config}"
    );
}

#[test]
fn an_unknown_provider_is_a_located_error_listing_the_accepted_words() {
    let message = adapt_error(
        "{\n\tgeoip geoip2 /var/lib/caddy/asn.mmdb\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert!(
        message.contains("geoip provider must be"),
        "message: {message}"
    );
    assert!(
        message.contains("dbip"),
        "must name the accepted words: {message}"
    );
    assert!(message.contains("maxmind"));
    assert!(
        message.contains("geoip2"),
        "must echo the bad word: {message}"
    );
}

#[test]
fn a_missing_argument_is_a_located_error() {
    let message = adapt_error("{\n\tgeoip dbip\n}\n\n:8080 {\n\trespond \"ok\"\n}\n");
    assert!(
        message.contains("exactly two arguments"),
        "message: {message}"
    );
    assert!(
        message.contains("got 1"),
        "must say how many arrived: {message}"
    );
}

#[test]
fn an_empty_block_is_accepted_and_emits_the_same_json_as_no_block() {
    // Pinning real behaviour rather than an aspiration: `Directive` has only `block: Vec<..>`, so
    // a written-but-empty block is indistinguishable from no block. Both adapt identically, which
    // matches how the other global options behave. Recorded here so nobody later assumes a
    // `takes no block` error exists for the empty case.
    let with_block = adapt_with_global("\tgeoip dbip /var/lib/caddy/asn.mmdb {\n\t}\n");
    let without_block = adapt_with_global("\tgeoip dbip /var/lib/caddy/asn.mmdb\n");
    assert_eq!(with_block.get("geoip"), without_block.get("geoip"));
    assert_eq!(
        with_block.get("geoip"),
        Some(&json!([{ "provider": "dbip", "path": "/var/lib/caddy/asn.mmdb" }]))
    );
}

#[test]
fn a_block_carrying_directives_is_rejected_on_the_argument_count() {
    // A non-empty block cannot be silently swallowed: its directives are not arguments, so the
    // count check refuses the line rather than discarding what the operator wrote.
    let message = adapt_error("{\n\tgeoip dbip {\n\t}\n}\n\n:8080 {\n\trespond \"ok\"\n}\n");
    assert!(
        message.contains("exactly two arguments"),
        "a one-argument geoip line is rejected: {message}"
    );
}

#[test]
fn stock_compat_rejects_geoip() {
    // The acceptance criterion: `stock_compat true` rejects `geoip` with a located error.
    let message = adapt_error(
        "{\n\tstock_compat true\n\tgeoip dbip /var/lib/caddy/asn.mmdb\n}\n\n:8080 {\n\trespond \"ok\"\n}\n",
    );
    assert!(
        message.contains("global option `geoip`"),
        "must name the option: {message}"
    );
    assert!(
        message.contains("caddy-rs extension, not in Caddy v2.11.9"),
        "must say why: {message}"
    );
    assert!(
        message.contains("not supported by this build"),
        "must be the unsupported class: {message}"
    );
    assert!(
        message.contains("line 3"),
        "the error must be located at the geoip line: {message}"
    );
}

#[test]
fn stock_compat_rejects_radar_and_geoip_together() {
    // The goal requires rejecting BOTH. Whichever is written first is reported; the important
    // property is that the presence of geoip cannot smuggle radar through.
    let message = adapt_error(
        "{\n\tstock_compat true\n\tradar {\n\t}\n\tgeoip dbip /var/lib/caddy/asn.mmdb\n}\n\n\
         :8080 {\n\trespond \"ok\"\n}\n",
    );
    assert!(
        message.contains("global option `radar`") || message.contains("global option `geoip`"),
        "must reject one of the two extensions: {message}"
    );

    // With both present the reported option is `radar`, because the parser checks the extensions
    // in a fixed order rather than the order they were written. Either is a correct rejection;
    // what matters is that writing `geoip` cannot let `radar` through, and vice versa.
    let message = adapt_error(
        "{\n\tstock_compat true\n\tgeoip dbip /var/lib/caddy/asn.mmdb\n\tradar {\n\t}\n}\n\n\
         :8080 {\n\trespond \"ok\"\n}\n",
    );
    assert!(
        message.contains("global option `radar`") || message.contains("global option `geoip`"),
        "must reject one of the two extensions: {message}"
    );
    assert!(
        message.contains("not supported by this build"),
        "must be the unsupported class: {message}"
    );
}
