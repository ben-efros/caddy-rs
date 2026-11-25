//! Caddyfile `file_server { symlinks ... }` adaptation.
//!
//! `symlinks` is a caddy-rs extension (Caddy follows every link). It maps to the handler's
//! `symlinks` JSON key; the default is left unset so the handler applies `within_root`.

use caddy_rs_config::adapt;
use serde_json::Value;

/// Adapt a site containing `file_server` with the given body and return the handler object.
fn file_server(body: &str) -> Result<Value, String> {
    let caddyfile = format!(":8080 {{\n\troot * /srv\n\tfile_server {{\n\t\t{body}\n\t}}\n}}\n");
    let adapted = adapt(&caddyfile).map_err(|error| error.to_string())?;
    let servers = adapted.config["apps"]["http"]["servers"]
        .as_object()
        .expect("servers object");
    let server = servers.values().next().expect("one server");
    let handlers = server["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .flat_map(|route| route["handle"].as_array().cloned().unwrap_or_default())
        .collect::<Vec<_>>();
    handlers
        .into_iter()
        .find(|handler| handler["handler"] == "file_server")
        .ok_or_else(|| format!("no file_server handler in {}", adapted.config))
}

#[test]
fn each_policy_is_emitted_as_the_json_string() {
    for policy in ["deny", "within_root", "follow"] {
        let handler = file_server(&format!("symlinks {policy}")).expect("adapts");
        assert_eq!(handler["symlinks"], policy);
    }
}

#[test]
fn the_policy_is_unset_by_default_so_the_handler_default_applies() {
    let handler = file_server("browse").expect("adapts");
    assert!(handler.get("symlinks").is_none(), "{handler}");
}

#[test]
fn it_combines_with_the_other_file_server_options() {
    let handler = file_server("hide *.env\n\t\tsymlinks follow\n\t\tbrowse").expect("adapts");
    assert_eq!(handler["symlinks"], "follow");
    assert_eq!(handler["hide"][0], "*.env");
    assert!(handler.get("browse").is_some());
}

#[test]
fn malformed_policies_are_located_errors() {
    for body in [
        "symlinks",
        "symlinks sometimes",
        "symlinks deny follow",
        "symlinks Deny",
    ] {
        let error = file_server(body).expect_err(body);
        assert!(error.contains("symlinks"), "{body}: {error}");
    }
}
