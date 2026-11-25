//! E3 (SEC-MEDIUM-AUTHN-PM): operator-supplied text that the data plane expands as Caddy
//! placeholders must never carry `{...}`.
//!
//! The runtime expands `{env.NAME}`, `{file.PATH}` and request placeholders in header values and
//! in a reverse-proxy `dial`, so an editor-role user who can set a CSP of `{env.CF_API_TOKEN}`
//! would otherwise have the process environment copied into every response of the site.

use super::*;

/// Every placeholder family that would be dangerous if it reached the data plane.
const DANGEROUS: &[&str] = &[
    "{env.CF_API_TOKEN}",
    "{file./etc/passwd}",
    "{http.request.header.X-Evil}",
    "{http.request.host}",
    "default-src 'self' {env.SECRET}",
    "{",
    "}",
    "a}b{c",
    "{{env.NESTED}}",
];

/// The five operator-supplied header fields, set one at a time.
type FieldSetter = fn(&mut SecurityHeadersConfig, String);

fn fields() -> Vec<(&'static str, FieldSetter)> {
    vec![
        (
            "security_headers.content_security_policy",
            |config, value| config.content_security_policy = Some(value),
        ),
        ("security_headers.permissions_policy", |config, value| {
            config.permissions_policy = Some(value)
        }),
        ("security_headers.x_frame_options", |config, value| {
            config.x_frame_options = Some(value)
        }),
        (
            "security_headers.x_content_type_options",
            |config, value| config.x_content_type_options = Some(value),
        ),
        ("security_headers.referrer_policy", |config, value| {
            config.referrer_policy = Some(value)
        }),
    ]
}

#[test]
fn every_header_field_rejects_placeholder_syntax_with_a_located_error() {
    for (path, set) in fields() {
        for dangerous in DANGEROUS {
            let mut config = SecurityHeadersConfig::default();
            set(&mut config, (*dangerous).to_string());
            let error = config
                .validate()
                .expect_err(&format!("{path} must reject {dangerous:?}"))
                .to_string();
            assert!(
                error.contains(path),
                "the error must name the JSON path `{path}`, got: {error}"
            );
        }
    }
}

#[test]
fn header_fields_reject_control_characters() {
    for (path, set) in fields() {
        for bad in ["a\r\nSet-Cookie: x=y", "a\nb", "a\0b", "tab\there"] {
            let mut config = SecurityHeadersConfig::default();
            set(&mut config, bad.to_string());
            let error = config
                .validate()
                .expect_err("control characters")
                .to_string();
            assert!(error.contains(path), "{error}");
        }
    }
}

#[test]
fn legitimate_header_values_are_still_accepted() {
    let config = SecurityHeadersConfig {
        content_security_policy: Some(
            "default-src 'self'; img-src 'self' https://cdn.example.com data:; \
             script-src 'self' 'nonce-abc123' 'strict-dynamic'; frame-ancestors 'none'; \
             report-uri https://csp.example.com/report?a=b&c=d"
                .to_string(),
        ),
        permissions_policy: Some(
            "geolocation=(), camera=(self \"https://meet.example.com\"), microphone=()".to_string(),
        ),
        x_frame_options: Some("SAMEORIGIN".to_string()),
        x_content_type_options: Some("nosniff".to_string()),
        referrer_policy: Some("no-referrer, strict-origin-when-cross-origin".to_string()),
        strict_transport_security: Some(SecurityHeadersHstsConfig {
            max_age: 31_536_000,
            include_subdomains: true,
            preload: true,
        }),
    };
    config.validate().expect("ordinary header values pass");
    // The secure defaults and the suppressed form (`None`) pass too.
    SecurityHeadersConfig::default().validate().unwrap();
    SecurityHeadersConfig {
        x_frame_options: None,
        x_content_type_options: None,
        referrer_policy: None,
        ..SecurityHeadersConfig::default()
    }
    .validate()
    .unwrap();
}

fn proxy_host_with_upstream(host: &str) -> Host {
    Host::new(
        HostId(1),
        vec!["example.com".to_string()],
        HostTls::disabled(),
        HostSpec::Proxy(ProxySpec::new(Upstream::new(
            UpstreamScheme::Http,
            host,
            8080,
        ))),
    )
}

#[test]
fn upstream_hosts_reject_placeholder_syntax() {
    for dangerous in [
        "{env.CF_API_TOKEN}",
        "{http.request.header.X-Target}",
        "{http.request.host}",
        "backend{env.X}",
        "{",
        "}",
        "[{env.X}]",
    ] {
        let error = Upstream::new(UpstreamScheme::Http, dangerous, 80)
            .validate()
            .expect_err(&format!("upstream host {dangerous:?} must be rejected"))
            .to_string();
        assert!(error.contains("upstream host"), "{error}");
        assert!(
            proxy_host_with_upstream(dangerous)
                .validate_structure()
                .is_err(),
            "{dangerous:?} must not pass host structure validation"
        );
    }
}

#[test]
fn legitimate_upstream_hosts_are_still_accepted() {
    for ok in [
        "10.0.0.5",
        "backend",
        "backend_1.internal",
        "my-service.default.svc.cluster.local",
        "2001:db8::1",
        "[2001:db8::1]",
        "localhost",
    ] {
        Upstream::new(UpstreamScheme::Https, ok, 443)
            .validate()
            .unwrap_or_else(|error| panic!("{ok} must stay valid: {error}"));
    }
}

#[test]
fn a_host_with_dangerous_security_headers_fails_structure_validation() {
    // Host create/update (`pm-hosts`) and route compilation both gate on `validate_structure`, so
    // the per-host headers cannot reach the compiler unvalidated.
    let mut host = proxy_host_with_upstream("10.0.0.5");
    host.security_headers = Some(SecurityHeadersConfig {
        content_security_policy: Some("{env.CF_API_TOKEN}".to_string()),
        ..SecurityHeadersConfig::default()
    });
    let error = host
        .validate_structure()
        .expect_err("must be rejected")
        .to_string();
    assert!(
        error.contains("security_headers.content_security_policy"),
        "{error}"
    );

    host.security_headers = Some(SecurityHeadersConfig::default());
    host.validate_structure().expect("safe headers pass");
}
