//! FastCGI Caddyfile adaptation: `php_fastcgi` and `reverse_proxy { transport fastcgi }`.
//!
//! The adapter emits Caddy's exact canonical expansion for the supported forms. The expanded
//! routes use Caddy's request `file` matcher, which this build does not implement yet
//! (T-ROUTE-027, `agent/file-matcher`); configurations that need it therefore adapt correctly but
//! cannot validate until that module lands (the same limitation applies to the wave-5 `try_files`
//! adaptation). Forms whose expanded output needs no `file` matcher — `php_fastcgi { index off }`
//! and the plain FastCGI transport — are validated here.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

fn validate(config: &Value) -> Result<(), String> {
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    let config =
        caddy_rs_core::Config::from_value(config.clone()).map_err(|error| error.to_string())?;
    caddy_rs_core::validate_config(&config, &registry).map_err(|error| error.to_string())?;
    Ok(())
}

#[test]
fn php_fastcgi_default_expansion_matches_caddy_shape() {
    let adapted = adapt("example.com {\n\tphp_fastcgi 127.0.0.1:9000\n}\n").expect("adapts");
    let routes = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"];
    // Site with a hostname is wrapped into a terminal subroute.
    let inner = &routes[0]["handle"][0]["routes"];
    assert_eq!(inner.as_array().map(Vec::len), Some(3));

    // 1. Directory canonicalisation redirect.
    assert_eq!(
        inner[0]["match"],
        json!([{
            "file": {"try_files": ["{http.request.uri.path}/index.php"]},
            "not": [{"path": ["*/"]}],
        }])
    );
    assert_eq!(
        inner[0]["handle"][0],
        json!({
            "handler": "static_response",
            "headers": {"Location": ["./{http.request.orig_uri.path.file_escaped}/{http.request.orig_uri.prefixed_query}"]},
            "status_code": 308,
        })
    );

    // 2. Index rewrite, with the file matcher's try policy/split path.
    assert_eq!(
        inner[1]["match"],
        json!([{
            "file": {
                "try_files": [
                    "{http.request.uri.path}",
                    "{http.request.uri.path}/index.php",
                    "index.php",
                ],
                "try_policy": "first_exist_fallback",
                "split_path": [".php"],
            }
        }])
    );
    assert_eq!(
        inner[1]["handle"][0],
        json!({"handler": "rewrite", "uri": "{http.matchers.file.relative}"})
    );

    // 3. PHP requests proxied through the FastCGI transport.
    assert_eq!(inner[2]["match"], json!([{"path": ["*.php"]}]));
    assert_eq!(
        inner[2]["handle"][0]["transport"],
        json!({"protocol": "fastcgi", "split_path": [".php"]})
    );
    assert_eq!(
        inner[2]["handle"][0]["upstreams"],
        json!([{"dial": "127.0.0.1:9000"}])
    );
}

#[test]
fn php_fastcgi_index_off_validates() {
    let adapted =
        adapt(":8884 {\n\tphp_fastcgi localhost:9000 {\n\t\tindex off\n\t}\n}\n").expect("adapts");
    // Only the PHP reverse_proxy route remains; it needs no file matcher.
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["match"],
        json!([{"path": ["*.php"]}])
    );
    validate(&adapted.config).expect("index off expansion validates");
}

#[test]
fn reverse_proxy_fastcgi_transport_expands_all_fields() {
    let adapted = adapt(
        ":8884 {\n\treverse_proxy unix//run/php.sock {\n\t\ttransport fastcgi {\n\
         \t\t\troot /srv/http\n\t\t\tsplit .php .php5\n\t\t\tenv APP_ENV production\n\
         \t\t\tresolve_root_symlink\n\t\t\tdial_timeout 3s\n\t\t\tread_timeout 10s\n\
         \t\t\twrite_timeout 20s\n\t\t\tcapture_stderr\n\t\t}\n\t\tlb_policy random\n\t}\n}\n",
    )
    .expect("adapts");
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(
        handler["transport"],
        json!({
            "protocol": "fastcgi",
            "root": "/srv/http",
            "split_path": [".php", ".php5"],
            "env": {"APP_ENV": "production"},
            "resolve_root_symlink": true,
            "dial_timeout": 3_000_000_000_i64,
            "read_timeout": 10_000_000_000_i64,
            "write_timeout": 20_000_000_000_i64,
            "capture_stderr": true,
        })
    );
    assert_eq!(
        handler["load_balancing"],
        json!({"selection_policy": {"policy": "random"}})
    );
    validate(&adapted.config).expect("fastcgi transport config validates");
}

#[test]
fn php_fastcgi_unsupported_forms_fail_loudly() {
    for (caddyfile, expected) in [
        (
            "example.com {\n\tphp_fastcgi localhost:9000 {\n\t\ttransport http\n\t}\n}\n",
            "does not accept a `transport` override",
        ),
        (
            "example.com {\n\tphp_fastcgi localhost:9000 {\n\t\tbogus_option x\n\t}\n}\n",
            "bogus_option",
        ),
        (
            "example.com {\n\tphp_fastcgi localhost:9000 {\n\t\tdial_timeout nope\n\t}\n}\n",
            "bad timeout value",
        ),
    ] {
        let error = adapt(caddyfile).expect_err("must be rejected loudly");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in: {error}"
        );
    }
}

#[test]
fn fastcgi_transport_unsupported_forms_fail_loudly() {
    for (caddyfile, expected) in [
        (
            ":8884 {\n\treverse_proxy localhost:9000 {\n\t\ttransport fastcgi {\n\t\t\tbogus x\n\t\t}\n\t}\n}\n",
            "unrecognized subdirective `bogus`",
        ),
        (
            ":8884 {\n\treverse_proxy localhost:9000 {\n\t\ttransport fastcgi extra\n\t}\n}\n",
            "does not take arguments",
        ),
        (
            ":8884 {\n\treverse_proxy https://localhost:9000 {\n\t\ttransport fastcgi\n\t}\n}\n",
            "cannot be combined",
        ),
    ] {
        let error = adapt(caddyfile).expect_err("must be rejected loudly");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in: {error}"
        );
    }
}

#[test]
fn php_fastcgi_expanded_form_uses_the_file_matcher() {
    // The upstream expanded-form fixture (T-CONF-013) writes the canonical php_fastcgi expansion
    // by hand: `file` request matchers, `{file_match.relative}` and `route`. All must adapt to
    // Caddy's JSON, with shorthand placeholders expanded before parsing.
    let adapted = adapt(
        ":8886 {\n\troute {\n\t\t@indexFiles {\n\t\t\tfile {\n\t\t\t\ttry_files {path} {path}/index.php index.php\n\t\t\t\tsplit_path .php\n\t\t\t}\n\t\t}\n\t\trewrite @indexFiles {file_match.relative}\n\t}\n}\n",
    )
    .expect("expanded form adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes");
    let inner = routes[0]["handle"][0]["routes"]
        .as_array()
        .expect("subroute routes");
    assert_eq!(
        inner[0]["match"][0]["file"],
        json!({
            "try_files": ["{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"],
            "split_path": [".php"],
        }),
        "{inner:?}"
    );
    assert_eq!(
        inner[0]["handle"][0]["uri"],
        "{http.matchers.file.relative}"
    );
}

#[test]
fn php_fastcgi_handle_response_is_adapted_like_reverse_proxy() {
    let adapted = adapt(
        ":8881 {\n\tphp_fastcgi app:9000 {\n\t\tenv FOO bar\n\t\t@error status 4xx\n\t\thandle_response @error {\n\t\t\trespond 500\n\t\t}\n\t}\n}\n",
    )
    .expect("php_fastcgi handle_response adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes");
    let handler = &routes[2]["handle"][0];
    assert_eq!(handler["handler"], "reverse_proxy");
    assert_eq!(
        handler["handle_response"][0]["match"],
        json!({"status_code": [4]})
    );
    assert_eq!(
        handler["transport"],
        json!({"protocol": "fastcgi", "split_path": [".php"], "env": {"FOO": "bar"}})
    );
}
