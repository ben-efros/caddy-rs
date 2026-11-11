//! Content-Security-Policy (CSP) directive parser and builder (caddy-rs extension).
//!
//! This module is a **caddy-rs extension with no Caddy equivalent**. Caddy v2.11.9 has no
//! Content-Security-Policy middleware: it only ships the generic `headers` handler
//! (`external/caddy/modules/caddyhttp/headers/headers.go`), which stages the literal string the
//! user configured and applies no parsing, validation or nonce substitution. Here a policy is
//! parsed into structured directives, validated against CSP Level 3 at load time, and rebuilt into
//! a canonical header value. The divergences are recorded in `docs/compatibility/T-HTTP-151.md`
//! (proposed register entry `DIV-0120`).
//!
//! # Representation and serialization
//!
//! [`CspPolicy`] stores the directives in a [`BTreeMap`] keyed by directive name, so
//! [`CspPolicy::to_header_value`] is deterministic: directives are emitted in lexicographic order,
//! sources in configuration order, a single space between sources and `; ` between directives. The
//! reverse direction is [`CspPolicy::parse_header_value`], and both directions round-trip exactly.
//! Configuration order is therefore not preserved; a policy is a set of directives, not a string.
//!
//! The [`CSP_NONCE_PLACEHOLDER`] token is a transparent source token, not a directive: it is kept
//! verbatim by [`CspPolicy::to_header_value`] (no synthetic nonce directive is serialized) and
//! replaced just before the header is emitted. Per response, call [`generate_nonce`] and then
//! [`expand_nonce`] on the header value (or [`CspPolicy::render_with_nonce`]).
//!
//! # Validation
//!
//! [`CspPolicy::from_json`] and [`CspPolicy::parse_header_value`] reject, with an
//! [`Error::InvalidConfig`] whose path locates the offending directive or source
//! (`policy.script-src[1]`), everything this module cannot represent faithfully:
//!
//! * unknown or malformed directive names (all standard CSP Level 3 directives are accepted; see
//!   [`CspPolicy::from_json`]);
//! * empty policies, empty source lists for directives that need one, and values on directives
//!   that take none (`upgrade-insecure-requests`, `block-all-mixed-content`);
//! * keywords outside the CSP keyword set, unterminated keywords, `'none'` combined with other
//!   sources, and keywords in directives where they carry no meaning (`'strict-dynamic'` outside
//!   the script-src family, for example);
//! * non-ASCII, whitespace, control or `;` characters inside a source token, which would break the
//!   header value;
//! * `report-uri` with anything but exactly one URL and `report-to` with anything but exactly one
//!   group name;
//! * duplicate directive names when parsing a header value (browsers keep the first one).
//!
//! Unlike the CSP specification, which tells browsers to ignore unknown directives and invalid
//! sources, this builder rejects them at load time so a typo cannot silently weaken a policy. That
//! is deliberate and documented as a divergence.
//!
//! A JSON directive value may be a string (a whitespace-separated source list, the same shape as
//! the header) or an array of source strings (one source per element, which is the only form in
//! which a whitespace or `;` character is diagnosed as being inside a source). A directive that
//! takes no value accepts an empty array or `""`; `sandbox` additionally accepts an empty list.
//!
//! # Nonce randomness
//!
//! [`generate_nonce`] uses `ring`'s [`ring::rand::SystemRandom`] (already a dependency of this
//! crate) to fill 16 bytes from the operating system CSPRNG and encodes them with URL-safe base64
//! without padding (22 characters, no `+`/`/`, so the value is also safe in an HTML attribute).
//! It panics if the OS CSPRNG is unavailable — there is no safe fallback for a CSP nonce, since a
//! predictable nonce defeats the nonce mechanism entirely. `ring` is used rather than a new
//! dependency; the CSP requirement is at least 16 random bytes, which this provides.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;
use serde_json::Value;

use crate::types::{Error, Result};

/// Placeholder token replaced by a generated nonce when the header value is rendered.
///
/// It is only valid in the script-src and style-src families, matching the CSP nonce grammar.
pub const CSP_NONCE_PLACEHOLDER: &str = "{csp.nonce}";

/// The standard CSP Level 3 directive names this builder accepts.
///
/// Sorted for readability; [`CspPolicy`] itself sorts directives when serializing.
const STANDARD_DIRECTIVES: &[&str] = &[
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "connect-src",
    "default-src",
    "font-src",
    "form-action",
    "frame-ancestors",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "navigate-to",
    "object-src",
    "plugin-types",
    "prefetch-src",
    "report-to",
    "report-uri",
    "require-trusted-types-for",
    "sandbox",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "trusted-types",
    "upgrade-insecure-requests",
    "worker-src",
];

/// The `sandbox` directive tokens defined by CSP Level 3 (plus the Chrome extensions).
const SANDBOX_TOKENS: &[&str] = &[
    "allow-downloads",
    "allow-downloads-without-user-activation",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-popups-to-escape-sandbox",
    "allow-presentation",
    "allow-same-origin",
    "allow-scripts",
    "allow-storage-access-by-user-activation",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
];

/// The directives whose sources may contain a nonce or hash source.
fn allows_nonce_or_hash(directive: &str) -> bool {
    matches!(
        directive,
        "script-src"
            | "script-src-elem"
            | "script-src-attr"
            | "style-src"
            | "style-src-elem"
            | "style-src-attr"
    )
}

/// The script-src family: directives that accept script-only keywords.
fn is_script_family(directive: &str) -> bool {
    matches!(
        directive,
        "script-src" | "script-src-elem" | "script-src-attr"
    )
}

/// The style-src family.
fn is_style_family(directive: &str) -> bool {
    matches!(directive, "style-src" | "style-src-elem" | "style-src-attr")
}

/// Directives whose source list is restricted to host/scheme sources and `'self'`/`'none'`.
fn is_navigation_family(directive: &str) -> bool {
    matches!(
        directive,
        "frame-ancestors" | "base-uri" | "form-action" | "navigate-to"
    )
}

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// A parsed, validated Content-Security-Policy.
///
/// Directives are held in a [`BTreeMap`], so equality is structural and serialization is
/// deterministic (lexicographic directive order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspPolicy {
    directives: BTreeMap<String, Vec<String>>,
}

impl CspPolicy {
    /// Parse and validate a CSP policy from its JSON representation.
    ///
    /// `value` must be a JSON object whose keys are directive names (validated against the CSP
    /// Level 3 directive set; unknown names are a located error) and whose values are either a
    /// string (a whitespace-separated source list) or an array of source strings. `path` is the
    /// JSON path of the object, used to build located error paths such as
    /// `security_headers.csp.script-src[1]`.
    pub fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            invalid(
                path,
                format!(
                    "a CSP policy must be a JSON object mapping directive names to source lists, \
                     got {}",
                    json_kind(value)
                ),
            )
        })?;
        if object.is_empty() {
            return Err(invalid(
                path,
                "a CSP policy must declare at least one directive",
            ));
        }
        let mut directives = BTreeMap::new();
        for (name, value) in object {
            let directive_path = format!("{path}.{name}");
            validate_directive_name(name, &directive_path)?;
            let sources = parse_json_sources(value, &directive_path)?;
            validate_directive(name, &sources, &directive_path)?;
            directives.insert(name.clone(), sources);
        }
        Ok(Self { directives })
    }

    /// Parse and validate a policy from an HTTP header value (`dir src...; dir2 src...`).
    ///
    /// An empty trailing segment (a trailing `;`) is tolerated. Duplicate directive names are
    /// rejected because browsers keep only the first one; the located path uses the `policy`
    /// prefix, for example `policy.script-src`.
    pub fn parse_header_value(value: &str) -> Result<Self> {
        if value.trim().is_empty() {
            return Err(invalid(
                "policy",
                "a CSP policy must declare at least one directive",
            ));
        }
        let mut directives: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for segment in value.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let mut tokens = segment.split_whitespace();
            let name = tokens
                .next()
                .expect("a non-empty segment has a first token");
            let sources: Vec<String> = tokens.map(str::to_string).collect();
            let directive_path = format!("policy.{name}");
            validate_directive_name(name, &directive_path)?;
            validate_directive(name, &sources, &directive_path)?;
            if directives.insert(name.to_string(), sources).is_some() {
                return Err(invalid(
                    &directive_path,
                    format!("duplicate CSP directive `{name}` in the header value"),
                ));
            }
        }
        if directives.is_empty() {
            return Err(invalid(
                "policy",
                "a CSP policy must declare at least one directive",
            ));
        }
        Ok(Self { directives })
    }

    /// Render the canonical header value: `dir src...; dir2 src...`, directives in lexicographic
    /// order, a single space between sources and `; ` between directives, no trailing `;`.
    ///
    /// The [`CSP_NONCE_PLACEHOLDER`] token is emitted verbatim; use [`Self::render_with_nonce`] or
    /// [`expand_nonce`] to substitute a generated nonce.
    pub fn to_header_value(&self) -> String {
        self.directives
            .iter()
            .map(|(name, sources)| {
                if sources.is_empty() {
                    name.clone()
                } else {
                    format!("{name} {}", sources.join(" "))
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Render the header value with a generated nonce substituted for [`CSP_NONCE_PLACEHOLDER`].
    pub fn render_with_nonce(&self, nonce: &str) -> String {
        expand_nonce(&self.to_header_value(), nonce)
    }

    /// The structured directives, in deterministic (lexicographic) order.
    pub fn directives(&self) -> &BTreeMap<String, Vec<String>> {
        &self.directives
    }

    /// Whether any directive uses [`CSP_NONCE_PLACEHOLDER`] and therefore needs a per-response
    /// nonce. This is derived, not a directive: it is never serialized.
    pub fn requires_nonce(&self) -> bool {
        self.directives
            .values()
            .any(|sources| sources.iter().any(|source| source == CSP_NONCE_PLACEHOLDER))
    }
}

/// Generate a CSP nonce: 16 bytes from the OS CSPRNG, URL-safe base64 without padding.
///
/// Nonces must be unpredictable and unique per response. Panics if the operating system CSPRNG is
/// unavailable, because there is no safe fallback for a security nonce.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("the operating system CSPRNG is required to generate a CSP nonce");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Replace every [`CSP_NONCE_PLACEHOLDER`] source token in `value` with `'nonce-<nonce>'`.
///
/// Only whole tokens (delimited by whitespace or `;`) are replaced, so a source that merely
/// contains the placeholder text is left alone. Separators are preserved exactly.
pub fn expand_nonce(value: &str, nonce: &str) -> String {
    let replacement = format!("'nonce-{nonce}'");
    let mut expanded = String::with_capacity(value.len() + replacement.len());
    let mut token_start = 0usize;
    for (index, character) in value.char_indices() {
        if character.is_whitespace() || character == ';' {
            push_nonce_token(&mut expanded, &value[token_start..index], &replacement);
            expanded.push(character);
            token_start = index + character.len_utf8();
        }
    }
    push_nonce_token(&mut expanded, &value[token_start..], &replacement);
    expanded
}

fn push_nonce_token(expanded: &mut String, token: &str, replacement: &str) {
    if token == CSP_NONCE_PLACEHOLDER {
        expanded.push_str(replacement);
    } else {
        expanded.push_str(token);
    }
}

/// Parse the JSON value of one directive into its source list.
fn parse_json_sources(value: &Value, path: &str) -> Result<Vec<String>> {
    match value {
        // The string form mirrors the header value: a whitespace-separated source list.
        Value::String(text) => Ok(text.split_whitespace().map(str::to_string).collect()),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                Value::String(source) if source.is_empty() => Err(invalid(
                    &format!("{path}[{index}]"),
                    "a source in the array form must not be empty",
                )),
                Value::String(source) => Ok(source.clone()),
                other => Err(invalid(
                    &format!("{path}[{index}]"),
                    format!("a source must be a string, got {}", json_kind(other)),
                )),
            })
            .collect(),
        other => Err(invalid(
            path,
            format!(
                "a directive value must be a string or an array of strings, got {}",
                json_kind(other)
            ),
        )),
    }
}

/// Validate a directive name against the CSP Level 3 set.
fn validate_directive_name(name: &str, path: &str) -> Result<()> {
    if name.is_empty() {
        return Err(invalid(path, "a CSP directive name must not be empty"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        return Err(invalid(
            path,
            format!(
                "invalid CSP directive name `{name}`: names are lower-case ASCII letters and `-`"
            ),
        ));
    }
    if !STANDARD_DIRECTIVES.contains(&name) {
        return Err(invalid(
            path,
            format!(
                "unknown CSP directive `{name}`: not in the CSP Level 3 directive set; \
                 unknown directives are rejected at load time instead of being ignored"
            ),
        ));
    }
    Ok(())
}

/// Validate one directive's source list.
fn validate_directive(name: &str, sources: &[String], path: &str) -> Result<()> {
    match name {
        "upgrade-insecure-requests" | "block-all-mixed-content" => {
            if !sources.is_empty() {
                return Err(invalid(path, format!("`{name}` takes no value")));
            }
            return Ok(());
        }
        "sandbox" => {
            for (index, token) in sources.iter().enumerate() {
                validate_sandbox_token(name, token, &format!("{path}[{index}]"))?;
            }
            return Ok(());
        }
        "report-uri" => {
            if sources.len() != 1 {
                return Err(invalid(
                    path,
                    format!(
                        "`report-uri` takes exactly one URL, got {} values",
                        sources.len()
                    ),
                ));
            }
            validate_report_uri(&sources[0], &format!("{path}[0]"))?;
            return Ok(());
        }
        "report-to" => {
            if sources.len() != 1 {
                return Err(invalid(
                    path,
                    format!(
                        "`report-to` takes exactly one group name, got {} values",
                        sources.len()
                    ),
                ));
            }
            validate_report_to(&sources[0], &format!("{path}[0]"))?;
            return Ok(());
        }
        "plugin-types" => {
            if sources.is_empty() {
                return Err(invalid(
                    path,
                    "`plugin-types` requires at least one MIME type",
                ));
            }
            for (index, source) in sources.iter().enumerate() {
                validate_mime_type(source, &format!("{path}[{index}]"))?;
            }
            return Ok(());
        }
        "require-trusted-types-for" => {
            if sources.len() != 1 {
                return Err(invalid(
                    path,
                    format!(
                        "`require-trusted-types-for` takes exactly one value, got {} values",
                        sources.len()
                    ),
                ));
            }
            if sources[0] != "'script'" {
                return Err(invalid(
                    &format!("{path}[0]"),
                    "`require-trusted-types-for` only accepts the value `'script'`",
                ));
            }
            return Ok(());
        }
        "trusted-types" => {
            if sources.is_empty() {
                return Err(invalid(path, "`trusted-types` requires at least one value"));
            }
            if sources.iter().any(|source| source == "'none'") && sources.len() > 1 {
                return Err(invalid(
                    path,
                    "`'none'` must be the only value of `trusted-types`",
                ));
            }
            for (index, source) in sources.iter().enumerate() {
                validate_trusted_types_value(source, &format!("{path}[{index}]"))?;
            }
            return Ok(());
        }
        _ => {}
    }

    if sources.is_empty() {
        return Err(invalid(
            path,
            format!("`{name}` requires at least one source"),
        ));
    }
    if sources.iter().any(|source| source == "'none'") && sources.len() > 1 {
        return Err(invalid(
            path,
            format!("`'none'` must be the only source of `{name}`; browsers ignore it otherwise"),
        ));
    }
    for (index, source) in sources.iter().enumerate() {
        validate_source(name, source, &format!("{path}[{index}]"))?;
    }
    Ok(())
}

/// Validate one source token of a source-list directive.
fn validate_source(directive: &str, source: &str, path: &str) -> Result<()> {
    if source.is_empty() {
        return Err(invalid(path, format!("empty source in `{directive}`")));
    }
    if !source.is_ascii() {
        return Err(invalid(
            path,
            format!("source `{source}` in `{directive}` contains non-ASCII characters"),
        ));
    }
    if source
        .bytes()
        .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b';')
    {
        return Err(invalid(
            path,
            format!(
                "source `{source}` in `{directive}` contains whitespace, control characters or `;`"
            ),
        ));
    }
    if source == CSP_NONCE_PLACEHOLDER {
        if !allows_nonce_or_hash(directive) {
            return Err(invalid(
                path,
                format!(
                    "the nonce placeholder `{CSP_NONCE_PLACEHOLDER}` in `{directive}` is only \
                     valid in the script-src and style-src families"
                ),
            ));
        }
        return Ok(());
    }
    if source.starts_with('\'') || source.ends_with('\'') {
        if !(source.starts_with('\'') && source.ends_with('\'') && source.len() >= 3) {
            return Err(invalid(
                path,
                format!("unterminated keyword `{source}` in `{directive}`"),
            ));
        }
        return validate_keyword(directive, &source[1..source.len() - 1], source, path);
    }
    validate_source_expression(directive, source, path)
}

/// Validate a quoted CSP keyword (the quotes have been stripped).
fn validate_keyword(directive: &str, keyword: &str, source: &str, path: &str) -> Result<()> {
    if is_navigation_family(directive) && !matches!(keyword, "self" | "none") {
        return Err(invalid(
            path,
            format!(
                "keyword `{source}` is not valid in `{directive}`; only `'self'` and `'none'` \
                 are allowed there"
            ),
        ));
    }
    match keyword {
        "self" | "none" | "unsafe-inline" | "unsafe-eval" => Ok(()),
        "strict-dynamic" | "wasm-unsafe-eval" | "inline-speculation-rules" => {
            if is_script_family(directive) {
                Ok(())
            } else {
                Err(invalid(
                    path,
                    format!(
                        "keyword `{source}` is only valid in the script-src family, not in `{directive}`"
                    ),
                ))
            }
        }
        "unsafe-hashes" | "report-sample" => {
            if is_script_family(directive) || is_style_family(directive) {
                Ok(())
            } else {
                Err(invalid(
                    path,
                    format!(
                        "keyword `{source}` is only valid in the script-src and style-src families, \
                         not in `{directive}`"
                    ),
                ))
            }
        }
        _ if keyword.starts_with("nonce-")
            || keyword.starts_with("sha256-")
            || keyword.starts_with("sha384-")
            || keyword.starts_with("sha512-") =>
        {
            if !allows_nonce_or_hash(directive) {
                return Err(invalid(
                    path,
                    format!(
                        "nonce and hash sources like `{source}` are only valid in the \
                         script-src and style-src families, not in `{directive}`"
                    ),
                ));
            }
            let value = keyword
                .split_once('-')
                .map(|(_, value)| value)
                .unwrap_or_default();
            if !is_base64_value(value) {
                return Err(invalid(
                    path,
                    format!("`{source}` in `{directive}` is not a valid base64 nonce or hash"),
                ));
            }
            Ok(())
        }
        _ => Err(invalid(
            path,
            format!("unknown CSP keyword `{source}` in `{directive}`"),
        )),
    }
}

/// Validate a non-keyword source expression: `*`, a scheme source, or a host source.
fn validate_source_expression(directive: &str, source: &str, path: &str) -> Result<()> {
    if source == "*" {
        return Ok(());
    }
    if let Some(scheme) = source.strip_suffix(':') {
        if is_valid_scheme(scheme) {
            return Ok(());
        }
        return Err(invalid(
            path,
            format!("invalid scheme in source `{source}` of `{directive}`"),
        ));
    }
    let authority = match source.split_once("://") {
        Some((scheme, authority)) => {
            if !is_valid_scheme(scheme) {
                return Err(invalid(
                    path,
                    format!("invalid scheme in source `{source}` of `{directive}`"),
                ));
            }
            authority
        }
        None => source,
    };
    let host_port = authority
        .split_once('/')
        .map_or(authority, |(host, _)| host);
    if host_port.is_empty() {
        return Err(invalid(
            path,
            format!("source `{source}` of `{directive}` has no host"),
        ));
    }
    let (host, port) = split_host_port(host_port);
    if !is_valid_host(host) {
        return Err(invalid(
            path,
            format!("invalid host in source `{source}` of `{directive}`"),
        ));
    }
    if let Some(port) = port {
        if port != "*" && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())) {
            return Err(invalid(
                path,
                format!("invalid port in source `{source}` of `{directive}`"),
            ));
        }
    }
    Ok(())
}

fn is_valid_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
}

/// Split `host[:port]`, honouring bracketed IPv6 literals.
fn split_host_port(host_port: &str) -> (&str, Option<&str>) {
    if let Some(end) = host_port.strip_prefix('[') {
        return match end.split_once(']') {
            Some((host, rest)) => (
                &host_port[..host.len() + 2],
                rest.strip_prefix(':').filter(|port| !port.is_empty()),
            ),
            None => (host_port, None),
        };
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (host, Some(port)),
        _ => (host_port, None),
    }
}

fn is_valid_host(host: &str) -> bool {
    if host == "*" {
        return true;
    }
    if let Some(literal) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return !literal.is_empty()
            && literal
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'));
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    for (index, label) in labels.iter().enumerate() {
        if *label == "*" {
            // The CSP wildcard is only a whole left-most label: `*.example.com`.
            if index != 0 || labels.len() == 1 {
                return false;
            }
            continue;
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'%'))
        {
            return false;
        }
    }
    true
}

fn is_base64_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

fn validate_sandbox_token(directive: &str, token: &str, path: &str) -> Result<()> {
    if !SANDBOX_TOKENS.contains(&token) {
        return Err(invalid(
            path,
            format!("invalid sandbox token `{token}` in `{directive}`"),
        ));
    }
    Ok(())
}

fn validate_report_uri(uri: &str, path: &str) -> Result<()> {
    validate_plain_token(uri, "report-uri", path)?;
    let absolute_url = uri
        .split_once(':')
        .is_some_and(|(scheme, _)| is_valid_scheme(scheme));
    if !absolute_url && !uri.starts_with('/') {
        return Err(invalid(
            path,
            format!(
                "`report-uri` value `{uri}` must be an absolute URL (with a scheme) or an \
                 absolute path starting with `/`"
            ),
        ));
    }
    Ok(())
}

fn validate_report_to(group: &str, path: &str) -> Result<()> {
    validate_plain_token(group, "report-to", path)?;
    if !group
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid(
            path,
            format!(
                "`report-to` group name `{group}` must contain only ASCII letters, digits, `-` \
                 and `_`"
            ),
        ));
    }
    Ok(())
}

fn validate_plain_token(value: &str, directive: &str, path: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid(
            path,
            format!("`{directive}` value must not be empty"),
        ));
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b';')
    {
        return Err(invalid(
            path,
            format!("`{directive}` value `{value}` contains whitespace, control characters or `;`"),
        ));
    }
    Ok(())
}

fn validate_mime_type(mime: &str, path: &str) -> Result<()> {
    let (kind, subtype) = mime.split_once('/').ok_or_else(|| {
        invalid(
            path,
            format!("`plugin-types` value `{mime}` is not a MIME type (`type/subtype`)"),
        )
    })?;
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&byte))
    };
    if !valid_part(kind) || !valid_part(subtype) {
        return Err(invalid(
            path,
            format!("`plugin-types` value `{mime}` is not a valid MIME type (`type/subtype`)"),
        ));
    }
    Ok(())
}

fn validate_trusted_types_value(value: &str, path: &str) -> Result<()> {
    match value {
        "*" | "'none'" | "'allow-duplicates'" => Ok(()),
        _ if value.starts_with('\'') => Err(invalid(
            path,
            format!("unknown `trusted-types` value `{value}`"),
        )),
        _ if !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) =>
        {
            Ok(())
        }
        _ => Err(invalid(
            path,
            format!(
                "`trusted-types` policy name `{value}` must contain only ASCII letters, digits, \
                 `-` and `_`"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;

    fn assert_invalid(json: &Value, expected_path: &str, expected_fragment: &str) {
        let error = CspPolicy::from_json(json, "policy").expect_err("expected InvalidConfig");
        match error {
            Error::InvalidConfig { path, message } => {
                assert_eq!(path, expected_path, "unexpected error path");
                assert!(
                    message.contains(expected_fragment),
                    "message {message:?} does not contain {expected_fragment:?}"
                );
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    fn assert_header_error(value: &str, expected_path: &str, expected_fragment: &str) {
        let error = CspPolicy::parse_header_value(value).expect_err("expected InvalidConfig");
        match error {
            Error::InvalidConfig { path, message } => {
                assert_eq!(path, expected_path, "unexpected error path");
                assert!(
                    message.contains(expected_fragment),
                    "message {message:?} does not contain {expected_fragment:?}"
                );
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn all_standard_directives_parse_and_serialize() {
        // Every directive in the CSP Level 3 set is exercised with a representative value.
        let policy = json!({
            "base-uri": ["'none'"],
            "block-all-mixed-content": [],
            "child-src": ["'self'"],
            "connect-src": ["'self'", "https://api.example"],
            "default-src": ["'self'", "https://cdn.example"],
            "font-src": ["'self'", "https://fonts.example"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'self'"],
            "frame-src": ["'self'"],
            "img-src": ["'self'", "data:", "https://img.example"],
            "manifest-src": ["'self'"],
            "media-src": ["'self'"],
            "navigate-to": ["'self'"],
            "object-src": ["'none'"],
            "plugin-types": ["application/pdf"],
            "prefetch-src": ["'self'"],
            "report-to": "csp-endpoint",
            "report-uri": "https://example.com/csp-report",
            "require-trusted-types-for": ["'script'"],
            "sandbox": [],
            "script-src": ["'self'", "https://cdn.example"],
            "script-src-attr": ["'unsafe-inline'"],
            "script-src-elem": ["'self'"],
            "style-src": ["'self'", "https://css.example"],
            "style-src-attr": ["'unsafe-inline'"],
            "style-src-elem": ["'self'"],
            "trusted-types": ["'none'"],
            "upgrade-insecure-requests": [],
            "worker-src": ["'self'"],
        });
        let parsed = CspPolicy::from_json(&policy, "policy").expect("valid policy");
        assert_eq!(
            parsed.directives().len(),
            STANDARD_DIRECTIVES.len(),
            "the test policy must cover every standard directive"
        );
        for directive in STANDARD_DIRECTIVES {
            assert!(
                parsed.directives().contains_key(*directive),
                "test policy is missing {directive}"
            );
        }

        let expected = "base-uri 'none'; block-all-mixed-content; child-src 'self'; \
                        connect-src 'self' https://api.example; \
                        default-src 'self' https://cdn.example; \
                        font-src 'self' https://fonts.example; form-action 'self'; \
                        frame-ancestors 'self'; frame-src 'self'; \
                        img-src 'self' data: https://img.example; manifest-src 'self'; \
                        media-src 'self'; navigate-to 'self'; object-src 'none'; \
                        plugin-types application/pdf; prefetch-src 'self'; \
                        report-to csp-endpoint; report-uri https://example.com/csp-report; \
                        require-trusted-types-for 'script'; sandbox; \
                        script-src 'self' https://cdn.example; script-src-attr 'unsafe-inline'; \
                        script-src-elem 'self'; style-src 'self' https://css.example; \
                        style-src-attr 'unsafe-inline'; style-src-elem 'self'; \
                        trusted-types 'none'; upgrade-insecure-requests; worker-src 'self'";
        assert_eq!(parsed.to_header_value(), expected);
        // The header value round-trips through the parser.
        assert_eq!(
            CspPolicy::parse_header_value(expected).expect("header round-trip"),
            parsed
        );

        // The string form is a whitespace-separated source list, matching the header syntax.
        let string_form = CspPolicy::from_json(
            &json!({"default-src": "'self' https://cdn.example"}),
            "policy",
        )
        .expect("string form");
        assert_eq!(
            string_form.to_header_value(),
            "default-src 'self' https://cdn.example"
        );
    }

    #[test]
    fn nonce_generation_and_placeholder_expansion() {
        let policy = CspPolicy::from_json(
            &json!({
                "script-src": ["'self'", CSP_NONCE_PLACEHOLDER, "'strict-dynamic'"],
                "style-src": ["'self'", CSP_NONCE_PLACEHOLDER],
            }),
            "policy",
        )
        .expect("valid policy with nonce placeholders");
        assert!(policy.requires_nonce());
        // Serialization keeps the placeholder verbatim and emits no bookkeeping directive.
        assert_eq!(
            policy.to_header_value(),
            "script-src 'self' {csp.nonce} 'strict-dynamic'; style-src 'self' {csp.nonce}"
        );

        let nonce = generate_nonce();
        // 16 random bytes in URL-safe base64 without padding -> 22 characters.
        assert_eq!(nonce.len(), 22);
        let decoded = URL_SAFE_NO_PAD.decode(&nonce).expect("base64 nonce");
        assert!(
            decoded.len() >= 16,
            "a CSP nonce needs at least 16 random bytes"
        );
        assert!(nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));

        let rendered = policy.render_with_nonce(&nonce);
        assert!(rendered.contains(&format!("'nonce-{nonce}'")));
        assert!(!rendered.contains(CSP_NONCE_PLACEHOLDER));
        assert_eq!(
            rendered,
            format!(
                "script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; style-src 'self' 'nonce-{nonce}'"
            )
        );
        rendered
            .parse::<HeaderValue>()
            .expect("rendered CSP is a valid header value");

        // Nonces are unique per response.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            assert!(seen.insert(generate_nonce()), "generated nonce repeated");
        }

        // expand_nonce only replaces whole source tokens.
        assert_eq!(
            expand_nonce("script-src 'self'", "abc"),
            "script-src 'self'"
        );
        assert_eq!(expand_nonce("{csp.nonce}x", "abc"), "{csp.nonce}x");
        assert_eq!(
            expand_nonce("default-src {csp.nonce}; script-src {csp.nonce}", "abc"),
            "default-src 'nonce-abc'; script-src 'nonce-abc'"
        );

        // A policy without the placeholder does not require a nonce.
        let plain = CspPolicy::parse_header_value("default-src 'self'").unwrap();
        assert!(!plain.requires_nonce());
    }

    #[test]
    fn strict_dynamic_and_unsafe_hashes_are_supported() {
        let parsed = CspPolicy::parse_header_value(
            "script-src 'self' 'strict-dynamic' https:; script-src-attr 'unsafe-hashes' \
             'sha256-abc123='",
        )
        .expect("strict-dynamic and unsafe-hashes are valid in the script-src family");
        assert_eq!(
            parsed.to_header_value(),
            "script-src 'self' 'strict-dynamic' https:; \
             script-src-attr 'unsafe-hashes' 'sha256-abc123='"
        );
        let from_json = CspPolicy::from_json(
            &json!({"script-src": ["'self'", "'strict-dynamic'", "'unsafe-hashes'"],
                    "style-src": ["'self'", "'report-sample'"]}),
            "policy",
        )
        .expect("valid policy");
        assert_eq!(
            from_json.to_header_value(),
            "script-src 'self' 'strict-dynamic' 'unsafe-hashes'; \
             style-src 'self' 'report-sample'"
        );

        // The keywords are rejected in directives where they carry no meaning.
        assert_invalid(
            &json!({"img-src": ["'self'", "'strict-dynamic'"]}),
            "policy.img-src[1]",
            "only valid in the script-src family",
        );
        assert_invalid(
            &json!({"img-src": ["'unsafe-hashes'"]}),
            "policy.img-src[0]",
            "script-src and style-src families",
        );
    }

    #[test]
    fn report_uri_and_report_to_are_supported() {
        let parsed = CspPolicy::parse_header_value(
            "default-src 'self'; report-uri https://example.com/csp-report; \
             report-to csp-endpoint",
        )
        .expect("report-uri and report-to parse");
        assert_eq!(
            parsed.to_header_value(),
            "default-src 'self'; report-to csp-endpoint; \
             report-uri https://example.com/csp-report"
        );
        // Both directive forms are accepted from JSON and round-trip.
        let from_json = CspPolicy::from_json(
            &json!({
                "default-src": "'self'",
                "report-uri": "/csp-report",
                "report-to": "csp-endpoint_2",
            }),
            "policy",
        )
        .expect("valid report directives");
        assert_eq!(
            CspPolicy::parse_header_value(&from_json.to_header_value()).unwrap(),
            from_json
        );
        assert_eq!(
            from_json.to_header_value(),
            "default-src 'self'; report-to csp-endpoint_2; report-uri /csp-report"
        );

        // Both take exactly one value: a source list does not fit.
        assert_invalid(
            &json!({"report-uri": ["https://a.example", "https://b.example"]}),
            "policy.report-uri",
            "exactly one URL",
        );
        assert_invalid(
            &json!({"report-to": ["a", "b"]}),
            "policy.report-to",
            "exactly one group name",
        );
        assert_invalid(
            &json!({"report-uri": ["relative/report"]}),
            "policy.report-uri[0]",
            "absolute URL",
        );
        assert_invalid(
            &json!({"report-to": ["bad group"]}),
            "policy.report-to[0]",
            "whitespace",
        );
    }

    #[test]
    fn invalid_directives_are_rejected_with_located_errors() {
        let cases: &[(Value, &str, &str)] = &[
            (json!({}), "policy", "at least one directive"),
            (
                json!({"scrpt-src": ["'self'"]}),
                "policy.scrpt-src",
                "unknown CSP directive `scrpt-src`",
            ),
            (
                // Unknown `*-src` names are rejected too: the fallback directives are all in the
                // standard set, so a `*-src` typo must not silently pass.
                json!({"frobnicate-src": ["'self'"]}),
                "policy.frobnicate-src",
                "unknown CSP directive `frobnicate-src`",
            ),
            (
                json!({"DEFAULT-SRC": ["'self'"]}),
                "policy.DEFAULT-SRC",
                "invalid CSP directive name",
            ),
            (
                json!({"default-src": []}),
                "policy.default-src",
                "requires at least one source",
            ),
            (
                json!({"default-src": 42}),
                "policy.default-src",
                "string or an array of strings",
            ),
            (
                json!({"default-src": ["'self'", 42]}),
                "policy.default-src[1]",
                "must be a string",
            ),
            (
                json!({"default-src": ["'self'", ""]}),
                "policy.default-src[1]",
                "must not be empty",
            ),
            (
                json!({"default-src": ["https://example.com; script-src *"]}),
                "policy.default-src[0]",
                "`;`",
            ),
            (
                json!({"default-src": ["https://exa mple.com"]}),
                "policy.default-src[0]",
                "whitespace",
            ),
            (
                json!({"default-src": ["héllo.example"]}),
                "policy.default-src[0]",
                "non-ASCII",
            ),
            (
                json!({"script-src": ["'strict-dynamic"]}),
                "policy.script-src[0]",
                "unterminated keyword",
            ),
            (
                json!({"script-src": ["'bogus'"]}),
                "policy.script-src[0]",
                "unknown CSP keyword",
            ),
            (
                json!({"default-src": ["'none'", "'self'"]}),
                "policy.default-src",
                "`'none'` must be the only source",
            ),
            (
                json!({"default-src": [CSP_NONCE_PLACEHOLDER]}),
                "policy.default-src[0]",
                "nonce placeholder",
            ),
            (
                json!({"upgrade-insecure-requests": ["'self'"]}),
                "policy.upgrade-insecure-requests",
                "takes no value",
            ),
            (
                json!({"sandbox": ["allow-everything"]}),
                "policy.sandbox[0]",
                "invalid sandbox token",
            ),
            (
                json!({"require-trusted-types-for": ["'default'"]}),
                "policy.require-trusted-types-for[0]",
                "only accepts the value `'script'`",
            ),
            (
                json!({"trusted-types": ["'none'", "my-policy"]}),
                "policy.trusted-types",
                "`'none'` must be the only value",
            ),
            (
                json!({"plugin-types": ["application/pdf; q=1"]}),
                "policy.plugin-types[0]",
                "not a valid MIME type",
            ),
        ];
        for (json, expected_path, expected_fragment) in cases {
            assert_invalid(json, expected_path, expected_fragment);
        }

        // Header parsing reports the same located problems with the `policy` prefix.
        assert_header_error("", "policy", "at least one directive");
        assert_header_error("   ;  ;", "policy", "at least one directive");
        assert_header_error(
            "script-src 'self'; script-src 'unsafe-inline'",
            "policy.script-src",
            "duplicate CSP directive",
        );
        assert_header_error("nope 'self'", "policy.nope", "unknown CSP directive");
        assert_header_error(
            "script-src",
            "policy.script-src",
            "requires at least one source",
        );
        assert_header_error(
            "img-src 'self' data:; script-src 'self' 'strict-dynamic' 'nonce-abc' 'bogus'",
            "policy.script-src[3]",
            "unknown CSP keyword",
        );
    }

    #[test]
    fn builder_produces_a_valid_deterministic_header_value() {
        let policy = CspPolicy::from_json(
            &json!({
                "default-src": ["'self'"],
                "script-src": ["'self'", "https://cdn.example", "'unsafe-eval'"],
                "report-uri": "https://example.com/csp-report",
                "frame-ancestors": ["'none'"],
            }),
            "security_headers.csp",
        )
        .expect("valid policy");

        let value = policy.to_header_value();
        // The result is a syntactically valid HTTP header value.
        let header: HeaderValue = value.parse().expect("valid header value");
        assert_eq!(header.to_str().unwrap(), value);
        // Deterministic: repeated calls and a reparse produce the same value.
        assert_eq!(policy.to_header_value(), value);
        assert_eq!(CspPolicy::parse_header_value(&value).unwrap(), policy);
        assert_eq!(
            CspPolicy::parse_header_value(&value)
                .unwrap()
                .to_header_value(),
            value
        );
        // No trailing separator and a stable lexicographic directive order.
        assert!(!value.ends_with(';'));
        assert_eq!(
            value,
            "default-src 'self'; frame-ancestors 'none'; \
             report-uri https://example.com/csp-report; \
             script-src 'self' https://cdn.example 'unsafe-eval'"
        );

        // A policy made of only a value-less directive still renders a valid header.
        let minimal = CspPolicy::from_json(&json!({"upgrade-insecure-requests": []}), "p")
            .expect("value-less directive");
        assert_eq!(minimal.to_header_value(), "upgrade-insecure-requests");
        minimal
            .to_header_value()
            .parse::<HeaderValue>()
            .expect("valid header value");
    }

    #[test]
    fn header_round_trip_normalizes_whitespace_and_tolerates_trailing_semicolon() {
        let parsed = CspPolicy::parse_header_value(
            "  default-src   'self'  https://cdn.example ;;  img-src 'self' data: ;",
        )
        .expect("tolerant header parsing");
        assert_eq!(
            parsed.to_header_value(),
            "default-src 'self' https://cdn.example; img-src 'self' data:"
        );
        // Round-trip is idempotent.
        let rendered = parsed.to_header_value();
        assert_eq!(CspPolicy::parse_header_value(&rendered).unwrap(), parsed);
    }
}
