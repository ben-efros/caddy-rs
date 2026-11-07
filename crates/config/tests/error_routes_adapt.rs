//! Differential Caddyfile adaptation for `handle_errors` and the `error` directive.
//!
//! Expected JSON is the output of real Caddy v2.11.9 (`caddy adapt --adapter caddyfile`) for the
//! same Caddyfile input (see `external/caddy/caddyconfig/httpcaddyfile/builtins.go`
//! `parseHandleErrors` and `httptype.go` error-route assembly).

use serde_json::{json, Value};

fn server_for(caddyfile: &str) -> Value {
    let adapted = caddy_rs_config::adapt(caddyfile).expect("Caddyfile adapts");
    adapted.config["apps"]["http"]["servers"]["srv0"].clone()
}

#[test]
fn handle_errors_adapts_byte_identically_for_a_catch_all_site() {
    let caddyfile = r#"
:8080 {
	error /private* "Unauthorized" 403
	error /hidden* "Not found" 404

	handle_errors 404 410 {
		respond "not here: {http.error.status_code} {http.error.message}"
	}

	handle_errors 5xx {
		respond "server error"
	}

	respond "ok"
}
"#;
    let server = server_for(caddyfile);
    let expected_routes = json!([
        {
            "match": [{"path": ["/private*"]}],
            "handle": [{"error": "Unauthorized", "handler": "error", "status_code": 403}]
        },
        {
            "match": [{"path": ["/hidden*"]}],
            "handle": [{"error": "Not found", "handler": "error", "status_code": 404}]
        },
        {"handle": [{"body": "ok", "handler": "static_response"}]}
    ]);
    assert_eq!(
        server["routes"], expected_routes,
        "normal routes must match Caddy"
    );
    let expected_errors = json!({
        "routes": [
            {
                "match": [{"expression": "{http.error.status_code} in [404, 410]"}],
                "handle": [{"handler": "subroute", "routes": [
                    {"handle": [{"body": "not here: {http.error.status_code} {http.error.message}", "handler": "static_response"}]}
                ]}]
            },
            {
                "match": [{"expression": "{http.error.status_code} >= 500 && {http.error.status_code} <= 599"}],
                "handle": [{"handler": "subroute", "routes": [
                    {"handle": [{"body": "server error", "handler": "static_response"}]}
                ]}]
            }
        ]
    });
    assert_eq!(
        server["errors"], expected_errors,
        "error routes must match Caddy"
    );
}

#[test]
fn handle_errors_adapts_byte_identically_for_a_host_site() {
    let caddyfile = r#"
example.com {
	error /private* "Unauthorized" 410
	error /hidden* "Not found" 404

	handle_errors {
		respond "fallback {http.error.status_code}"
	}
	handle_errors 4xx {
		respond "client error"
	}

	respond "ok"
}
"#;
    let server = server_for(caddyfile);
    let expected_routes = json!([
        {
            "match": [{"host": ["example.com"]}],
            "handle": [{"handler": "subroute", "routes": [
                {
                    "match": [{"path": ["/private*"]}],
                    "handle": [{"error": "Unauthorized", "handler": "error", "status_code": 410}]
                },
                {
                    "match": [{"path": ["/hidden*"]}],
                    "handle": [{"error": "Not found", "handler": "error", "status_code": 404}]
                },
                {"handle": [{"body": "ok", "handler": "static_response"}]}
            ]}],
            "terminal": true
        }
    ]);
    assert_eq!(server["routes"], expected_routes);
    let expected_errors = json!({
        "routes": [{
            "match": [{"host": ["example.com"]}],
            "handle": [{"handler": "subroute", "routes": [
                {
                    "match": [{"expression": "{http.error.status_code} >= 400 && {http.error.status_code} <= 499"}],
                    "handle": [{"handler": "subroute", "routes": [
                        {"handle": [{"body": "client error", "handler": "static_response"}]}
                    ]}]
                },
                {
                    "handle": [{"handler": "subroute", "routes": [
                        {"handle": [{"body": "fallback {http.error.status_code}", "handler": "static_response"}]}
                    ]}]
                }
            ]}],
            "terminal": true
        }]
    });
    assert_eq!(server["errors"], expected_errors);
}

#[test]
fn handle_errors_status_values_are_validated_loudly() {
    for caddyfile in [
        ":8080 {\n\thandle_errors 40 {\n\t\trespond \"x\"\n\t}\n}\n",
        ":8080 {\n\thandle_errors nope {\n\t\trespond \"x\"\n\t}\n}\n",
    ] {
        let error = caddy_rs_config::adapt(caddyfile).expect_err("bad status value must be loud");
        assert!(error.to_string().contains("bad status value"), "{error}");
    }
    let caddyfile = ":8080 {\n\thandle_errors 4xx {\n\t\trespond \"x\"\n\t}\n}\n";
    let adapted = caddy_rs_config::adapt(caddyfile).expect("4xx class adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["errors"]["routes"][0]["match"][0]
            ["expression"],
        json!("{http.error.status_code} >= 400 && {http.error.status_code} <= 499")
    );
}
