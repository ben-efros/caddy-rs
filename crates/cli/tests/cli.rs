//! CLI integration tests. These exercise the compiled binary, not the library API.

use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_caddy-rs")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn version_reports_implementation_and_caddy_baseline() {
    let (code, stdout, _stderr) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("caddy-rs 0.1.0"), "{stdout}");
    assert!(stdout.contains("v2.11.7"), "{stdout}");

    let (code, stdout, _stderr) = run(&["version", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["caddy_compat_baseline"], "v2.11.7");
}

#[test]
fn list_modules_includes_implemented_handlers() {
    let (code, stdout, _stderr) = run(&["list-modules", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let modules = value["modules"].as_array().expect("modules array");
    let ids: Vec<&str> = modules
        .iter()
        .filter_map(|module| module["id"].as_str())
        .collect();
    assert!(ids.contains(&"http.handlers.reverse_proxy"), "{ids:?}");
    assert!(ids.contains(&"http.handlers.file_server"), "{ids:?}");
    assert!(ids.contains(&"http.matchers.host"), "{ids:?}");
}

#[test]
fn adapts_caddyfile_to_caddy_json() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, "example.com {\n\trespond \"hello\"\n}\n").unwrap();
    let (code, stdout, stderr) = run(&["adapt", "--config", config.to_str().unwrap(), "--pretty"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("adapted JSON");
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["listen"][0],
        ":443"
    );
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["routes"][0]["match"][0]["host"][0],
        "example.com"
    );
}

#[test]
fn validate_accepts_and_rejects() {
    let directory = tempfile::tempdir().unwrap();
    let valid = directory.path().join("valid.json");
    std::fs::write(
        &valid,
        serde_json::to_string(&serde_json::json!({
            "admin": {"disabled": true},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, stdout, stderr) = run(&["validate", "--config", valid.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Valid configuration"));

    let invalid = directory.path().join("invalid.json");
    std::fs::write(
        &invalid,
        serde_json::to_string(&serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "not_a_module"}]}]
            }}}}
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, _stdout, stderr) = run(&["validate", "--config", invalid.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("not_a_module"), "{stderr}");
}

#[test]
fn adapt_surfaces_unsupported_directive_as_error() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, ":80 {\n\tsome_unknown_directive foo\n}\n").unwrap();
    let (code, _stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().unwrap(),
        "--adapter",
        "caddyfile",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("some_unknown_directive"), "{stderr}");
    assert!(stderr.contains("docs/compatibility"), "{stderr}");
}
