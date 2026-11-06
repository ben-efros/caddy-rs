//! Differential adaptation for `reverse_proxy`'s `handle_response` blocks and response matchers.
//!
//! The Caddyfile and expected JSON are the upstream v2.11.7 fixture
//! `external/caddy/caddytest/integration/caddyfile_adapt/reverse_proxy_handle_response.caddyfiletest`
//! (source: `modules/caddyhttp/reverseproxy/caddyfile.go` `FinalizeUnmarshalCaddyfile` and
//! `modules/caddyhttp/responsematchers.go`).

use serde_json::{json, Value};

const CADDYFILE: &str = r#":8884

reverse_proxy 127.0.0.1:65535 {
	@500 status 500
	replace_status @500 400

	@all status 2xx 3xx 4xx 5xx
	replace_status @all {http.error.status_code}

	replace_status {http.error.status_code}

	@accel header X-Accel-Redirect *
	handle_response @accel {
		respond "Header X-Accel-Redirect!"
	}

	@another {
		header X-Another *
	}
	handle_response @another {
		respond "Header X-Another!"
	}

	@401 status 401
	handle_response @401 {
		respond "Status 401!"
	}

	handle_response {
		respond "Any! This should be last in the JSON!"
	}

	@403 {
		status 403
	}
	handle_response @403 {
		respond "Status 403!"
	}

	@multi {
		status 401 403
		status 404
		header Foo *
		header Bar *
	}
	handle_response @multi {
		respond "Headers Foo, Bar AND statuses 401, 403 and 404!"
	}

	@200 status 200
	handle_response @200 {
		copy_response_headers {
			include Foo Bar
		}
		respond "Copied headers from the response"
	}

	@201 status 201
	handle_response @201 {
		header Foo "Copying the response"
		copy_response 404
	}
}
"#;

fn expected_routes() -> Value {
    json!([
        {
            "handle": [{
                "handle_response": [
                    {"match": {"status_code": [500]}, "status_code": 400},
                    {"match": {"status_code": [2, 3, 4, 5]}, "status_code": "{http.error.status_code}"},
                    {
                        "match": {"headers": {"X-Accel-Redirect": ["*"]}},
                        "routes": [{"handle": [{"body": "Header X-Accel-Redirect!", "handler": "static_response"}]}]
                    },
                    {
                        "match": {"headers": {"X-Another": ["*"]}},
                        "routes": [{"handle": [{"body": "Header X-Another!", "handler": "static_response"}]}]
                    },
                    {
                        "match": {"status_code": [401]},
                        "routes": [{"handle": [{"body": "Status 401!", "handler": "static_response"}]}]
                    },
                    {
                        "match": {"status_code": [403]},
                        "routes": [{"handle": [{"body": "Status 403!", "handler": "static_response"}]}]
                    },
                    {
                        "match": {
                            "headers": {"Bar": ["*"], "Foo": ["*"]},
                            "status_code": [401, 403, 404]
                        },
                        "routes": [{"handle": [{"body": "Headers Foo, Bar AND statuses 401, 403 and 404!", "handler": "static_response"}]}]
                    },
                    {
                        "match": {"status_code": [200]},
                        "routes": [{"handle": [
                            {"handler": "copy_response_headers", "include": ["Foo", "Bar"]},
                            {"body": "Copied headers from the response", "handler": "static_response"}
                        ]}]
                    },
                    {
                        "match": {"status_code": [201]},
                        "routes": [{"handle": [
                            {"handler": "headers", "response": {"set": {"Foo": ["Copying the response"]}}},
                            {"handler": "copy_response", "status_code": 404}
                        ]}]
                    },
                    {"status_code": "{http.error.status_code}"},
                    {
                        "routes": [{"handle": [{"body": "Any! This should be last in the JSON!", "handler": "static_response"}]}]
                    }
                ],
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "127.0.0.1:65535"}]
            }]
        }
    ])
}

#[test]
fn reverse_proxy_handle_response_adapts_byte_identically() {
    let adapted = caddy_rs_config::adapt(CADDYFILE).expect("Caddyfile adapts");
    let server = &adapted.config["apps"]["http"]["servers"]["srv0"];
    assert_eq!(server["listen"], json!([":8884"]));
    assert_eq!(
        server["routes"],
        expected_routes(),
        "adapted JSON must match real Caddy v2.11.7 (got: {})",
        server["routes"]
    );
}

#[test]
fn handle_response_configs_are_validated_loudly() {
    // Unknown response matcher text, missing matchers, and too many arguments are located errors.
    for caddyfile in [
        ":8080 {\n\treverse_proxy localhost:9000 {\n\t\t@e nope 500\n\t\thandle_response @e {\n\t\t\trespond \"x\"\n\t\t}\n\t}\n}\n",
        ":8080 {\n\treverse_proxy localhost:9000 {\n\t\thandle_response @missing {\n\t\t\trespond \"x\"\n\t\t}\n\t}\n}\n",
        ":8080 {\n\treverse_proxy localhost:9000 {\n\t\thandle_response @a @b {\n\t\t\trespond \"x\"\n\t\t}\n\t}\n}\n",
        ":8080 {\n\treverse_proxy localhost:9000 {\n\t\t@h header\n\t\thandle_response @h {\n\t\t\trespond \"x\"\n\t\t}\n\t}\n}\n",
    ] {
        let error = caddy_rs_config::adapt(caddyfile)
            .expect_err("invalid handle_response configuration must be loud");
        let message = error.to_string();
        assert!(
            message.contains("response matcher")
                || message.contains("status")
                || message.contains("handle_response")
                || message.contains("header"),
            "{message}"
        );
    }
}
