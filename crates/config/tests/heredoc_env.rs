//! End-to-end tests for Caddyfile heredocs, backslash continuation, and `{$ENV}` placeholders.
//!
//! The heredoc cases are derived from Caddy v2.11.7's own golden adapter fixtures in
//! `caddytest/integration/caddyfile_adapt/heredoc*.caddyfiletest`, so the expected JSON (and the
//! expected error text for the rejected inputs) is what Caddy itself produces.

use caddy_rs_config::{adapt, expand_env_vars, expand_env_vars_with, parse};
use serde_json::Value;

/// Caddyfile portion of upstream `heredoc.caddyfiletest`.
const HEREDOC_CADDYFILE: &str = "\
example.com {
\trespond <<EOF
    <html>
      <head><title>Foo</title>
      <body>Foo</body>
    </html>
    EOF 200
}
";

/// Expected JSON portion of upstream `heredoc.caddyfiletest`.
const HEREDOC_EXPECTED_JSON: &str = r#"{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"example.com"
									]
								}
							],
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "\u003chtml\u003e\n  \u003chead\u003e\u003ctitle\u003eFoo\u003c/title\u003e\n  \u003cbody\u003eFoo\u003c/body\u003e\n\u003c/html\u003e",
													"handler": "static_response",
													"status_code": 200
												}
											]
										}
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		}
	}
}"#;

/// Caddyfile portion of upstream `heredoc_extra_indentation.caddyfiletest`.
const HEREDOC_EXTRA_INDENTATION_CADDYFILE: &str = "\
:80

handle {
\trespond <<END
        line1
        line2
  END
}
";

/// Expected JSON portion of upstream `heredoc_extra_indentation.caddyfiletest`.
const HEREDOC_EXTRA_INDENTATION_EXPECTED_JSON: &str = r#"{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":80"
					],
					"routes": [
						{
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"body": "      line1\n      line2",
													"handler": "static_response"
												}
											]
										}
									]
								}
							]
						}
					]
				}
			}
		}
	}
}"#;

fn adapt_error(caddyfile: &str) -> String {
    adapt(caddyfile)
        .expect_err("adapter must reject this Caddyfile")
        .to_string()
}

#[test]
fn heredoc_adapts_to_caddy_golden_json() {
    let expected: Value = serde_json::from_str(HEREDOC_EXPECTED_JSON).expect("golden JSON");
    let adapted = adapt(HEREDOC_CADDYFILE).expect("heredoc fixture adapts");
    assert_eq!(adapted.config, expected);
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn heredoc_extra_indentation_adapts_to_caddy_golden_json() {
    let expected: Value =
        serde_json::from_str(HEREDOC_EXTRA_INDENTATION_EXPECTED_JSON).expect("golden JSON");
    let adapted = adapt(HEREDOC_EXTRA_INDENTATION_CADDYFILE).expect("heredoc fixture adapts");
    assert_eq!(adapted.config, expected);
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn heredoc_blank_lines_are_preserved_through_adaptation() {
    let adapted = adapt(":80 {\n\trespond <<EOF\nline one\n\nline two\nEOF\n}\n").expect("adapts");
    let body = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"]
        .as_str()
        .expect("body is a string");
    assert_eq!(body, "line one\n\nline two");
}

#[test]
fn heredoc_mismatched_whitespace_error_matches_caddy() {
    // Upstream `heredoc_mismatched_whitespace.caddyfiletest`.
    let error = adapt_error(":80\n\nhandle {\n\trespond <<END\n\tline1\n\tline2\n  END\n}\n");
    assert!(
        error.contains(
            "mismatched leading whitespace in heredoc <<END on line #5 [\tline1], expected \
             whitespace [  ] to match the closing marker"
        ),
        "{error}"
    );
}

#[test]
fn heredoc_extra_indentation_error_matches_caddy() {
    // Upstream `heredoc_incomplete.caddyfiletest`, which actually terminates on the `EOF`
    // substring inside the trailing comment and therefore reports mismatched whitespace.
    let error =
        adapt_error(":80\n\nhandle {\n    respond <<EOF\n    Hello\n# missing EOF marker\n}\n");
    assert!(
        error.contains(
            "mismatched leading whitespace in heredoc <<EOF on line #5 [    Hello], expected \
             whitespace [# missing ] to match the closing marker"
        ),
        "{error}"
    );
}

#[test]
fn heredoc_invalid_marker_error_matches_caddy() {
    // Upstream `heredoc_invalid_marker.caddyfiletest`.
    let error = adapt_error(":80\n\nhandle {\n    respond <<END!\n    Hello\n    END!\n}\n");
    assert!(
        error.contains(
            "heredoc marker on line #4 must contain only alphanumeric characters, dashes and \
             underscores; got 'END!'"
        ),
        "{error}"
    );
}

#[test]
fn heredoc_too_many_angle_brackets_error_matches_caddy() {
    // Upstream `heredoc_too_many_angle_brackets.caddyfiletest`.
    let error = adapt_error(":80\n\nhandle {\n    respond <<<END\n    Hello\n    END\n}\n");
    assert!(
        error.contains("too many '<' for heredoc on line #4; only use two, for example <<END"),
        "{error}"
    );
}

#[test]
fn heredoc_missing_marker_is_a_normal_token_like_caddy() {
    // Upstream `heredoc_missing_marker.caddyfiletest`: `<< ` followed by a space is the ordinary
    // token `<<`, so the following line is parsed as a directive and rejected by the adapter.
    let error = adapt_error(":80\n\nhandle {\n    respond << \n    Hello\n    END\n}\n");
    assert!(error.contains("Hello"), "{error}");
}

#[test]
fn backslash_continuation_chains_arguments_end_to_end() {
    let adapted = adapt(":80 {\n\trespond hello \\\n200\n}\n").expect("continuation adapts");
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(handler["body"], Value::String("hello".to_string()));
    assert_eq!(handler["status_code"], Value::from(200));
}

#[test]
fn env_placeholder_in_site_address_uses_process_environment() {
    std::env::set_var("CADDY_RS_TEST_PORT", "8081");
    let adapted = adapt(":{$CADDY_RS_TEST_PORT:9999} {\n\trespond ok\n}\n").expect("adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["listen"][0],
        Value::String(":8081".to_string())
    );
    std::env::remove_var("CADDY_RS_TEST_PORT");
}

#[test]
fn env_placeholder_default_is_used_when_variable_is_unset() {
    std::env::remove_var("CADDY_RS_TEST_PORT_DEFAULT");
    let adapted =
        adapt(":{$CADDY_RS_TEST_PORT_DEFAULT:8082} {\n\trespond ok\n}\n").expect("adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["listen"][0],
        Value::String(":8082".to_string())
    );
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn missing_env_variable_substitutes_empty_string_and_warns_through_adapt() {
    std::env::remove_var("CADDY_RS_TEST_MISSING");
    let error = adapt(":{$CADDY_RS_TEST_MISSING} {\n\trespond ok\n}\n")
        .expect_err("`:` with an empty port is not a usable site address");
    assert!(
        error.to_string().contains("is not a valid TCP/UDP port"),
        "{error}"
    );
}

#[test]
fn missing_env_variable_warning_is_surfaced_by_the_adapter() {
    std::env::remove_var("CADDY_RS_TEST_MISSING_BODY");
    let adapted = adapt(":80 {\n\trespond \"prefix-{$CADDY_RS_TEST_MISSING_BODY}\"\n}\n")
        .expect("adapts with an empty substitution");
    assert_eq!(adapted.warnings.len(), 1, "{:?}", adapted.warnings);
    assert!(
        adapted.warnings[0].contains("CADDY_RS_TEST_MISSING_BODY"),
        "{:?}",
        adapted.warnings
    );
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(handler["body"], Value::String("prefix-".to_string()));
}

#[test]
fn env_placeholder_is_expanded_inside_a_heredoc_body() {
    std::env::set_var("CADDY_RS_TEST_HEREDOC_VALUE", "expanded");
    let adapted = adapt(":80 {\n\trespond <<EOF\nvalue: {$CADDY_RS_TEST_HEREDOC_VALUE}\nEOF\n}\n")
        .expect("adapts");
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(
        handler["body"],
        Value::String("value: expanded".to_string())
    );
    std::env::remove_var("CADDY_RS_TEST_HEREDOC_VALUE");
}

#[test]
fn expand_env_vars_matches_caddy_replacement_rules() {
    let expansion = expand_env_vars_with(
        "{$A}{$A} {$B:default} foo{$C:bar}baz {$D:$A} {$} {$$} {$LONGER NAME} {$UNTERMINATED",
        |name| match name {
            "A" => Some("a".to_string()),
            "D" => Some("d".to_string()),
            _ => None,
        },
    );
    // One-level expansion, `:default` split on the first colon, literal `$` in defaults, `{$}`
    // untouched, `{$$}` looked up as the variable named `$` (unset -> empty).
    assert_eq!(
        expansion.source,
        "aa default foobarbaz d {$}   {$UNTERMINATED"
    );
    // Missing without a default: the `$`-named variable from `{$$}` and the space-containing name
    // from `{$LONGER NAME}`. `{$UNTERMINATED` has no closing brace, so Caddy stops scanning there.
    assert_eq!(expansion.warnings.len(), 2, "{:?}", expansion.warnings);
    assert!(
        expansion
            .warnings
            .iter()
            .any(|w| w.contains("`LONGER NAME`")),
        "{:?}",
        expansion.warnings
    );
}

#[test]
fn expand_env_vars_reads_the_process_environment() {
    std::env::set_var("CADDY_RS_TEST_EXPANSION", "value");
    let expansion = expand_env_vars("before-{$CADDY_RS_TEST_EXPANSION:default}-after");
    assert_eq!(expansion.source, "before-value-after");
    assert!(expansion.warnings.is_empty());

    std::env::remove_var("CADDY_RS_TEST_EXPANSION");
    let expansion = expand_env_vars("before-{$CADDY_RS_TEST_EXPANSION:default}-after");
    assert_eq!(expansion.source, "before-default-after");
    assert!(expansion.warnings.is_empty(), "{:?}", expansion.warnings);
}

#[test]
fn env_expansion_happens_before_lexing_so_values_may_introduce_tokens() {
    std::env::set_var("CADDY_RS_TEST_STRUCTURE", "header X-Env yes");
    let file = parse(":80 {\n\t{$CADDY_RS_TEST_STRUCTURE}\n}\n").expect("parses");
    let directive = &file.sites[0].directives[0];
    assert_eq!(directive.name, "header");
    assert_eq!(directive.args, vec!["X-Env".to_string(), "yes".to_string()]);
    std::env::remove_var("CADDY_RS_TEST_STRUCTURE");
}

#[test]
fn env_replacement_parity_with_caddy_table() {
    // Ported from Caddy v2.11.7 `caddyconfig/caddyfile/parse_test.go`,
    // `TestEnvironmentReplacement`; the same lookup table is used here.
    let cases = [
        ("", ""),
        ("foo", "foo"),
        ("{$NOT_SET}", ""),
        ("foo{$NOT_SET}bar", "foobar"),
        ("{$FOOBAR}", "foobar"),
        ("foo {$FOOBAR} bar", "foo foobar bar"),
        ("foo{$FOOBAR}bar", "foofoobarbar"),
        ("foo\n{$FOOBAR}\nbar", "foo\nfoobar\nbar"),
        ("{$FOOBAR} {$FOOBAR}", "foobar foobar"),
        ("{$FOOBAR}{$FOOBAR}", "foobarfoobar"),
        ("{$CHAINED}", "$FOOBAR"),
        ("{$FOO:default}", "default"),
        ("foo{$BAR:bar}baz", "foobarbaz"),
        ("foo{$BAR:$FOOBAR}baz", "foo$FOOBARbaz"),
        ("{$FOOBAR", "{$FOOBAR"),
        ("{$LONGER_NAME $FOOBAR}", ""),
        ("{$}", "{$}"),
        ("{$$}", ""),
        ("{$", "{$"),
        ("}{$", "}{$"),
    ];
    for (input, expected) in cases {
        let expansion = expand_env_vars_with(input, |name| match name {
            "FOOBAR" => Some("foobar".to_string()),
            "CHAINED" => Some("$FOOBAR".to_string()),
            _ => None,
        });
        assert_eq!(expansion.source, expected, "input {input:?}");
    }
}

#[test]
fn env_warning_line_numbers_survive_multiline_replacements() {
    // The first variable's value contains a newline, so the second warning must still name the
    // line in the caller's original source (line 3), not the expanded source's line 4.
    let expansion = expand_env_vars_with("{$MULTI}\n{$MISSING}\n", |name| {
        (name == "MULTI").then(|| "one\ntwo".to_string())
    });
    assert_eq!(expansion.source, "one\ntwo\n\n");
    assert_eq!(expansion.warnings.len(), 1, "{:?}", expansion.warnings);
    assert!(
        expansion.warnings[0].contains("Caddyfile line 2"),
        "{:?}",
        expansion.warnings
    );
}
