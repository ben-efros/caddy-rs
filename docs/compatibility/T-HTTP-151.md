# T-HTTP-151 compatibility note — CSP directive parser and builder

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task adds `crates/http/src/csp.rs`: a parser, validator and builder for Content-Security-Policy
values. The note below states only behaviour this implementation can point at a test for; the
proposed register entry is at the end.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- Caddy v2.11.9 has **no built-in Content-Security-Policy middleware**. There is no
  `http.handlers.csp` (or similarly named) module in the standard module set.
- The only upstream CSP surface is the generic `headers` handler,
  `external/caddy/modules/caddyhttp/headers/headers.go`. Its `Header` operations
  (`set`/`add`/`delete`/`replace`, with `defer` and `>`/`<` placeholder support) stage the
  configured literal string; it does not parse directives, validate source lists, generate nonces
  or know any CSP grammar. A user writes `Content-Security-Policy` as an opaque value and Caddy
  emits it verbatim.
- Consequently there is no upstream CSP parsing or serialization behaviour to match: the structured
  behaviour described here is a caddy-rs extension, and the deliberate differences from "a raw
  header value passed through unchanged" are listed under residual divergences.

## Implemented behaviour

`crates/http/src/csp.rs` exposes `CspPolicy` (a `BTreeMap` of directive name to source list), plus
`parse_header_value`, `to_header_value`, `from_json`, `CSP_NONCE_PLACEHOLDER`, `generate_nonce`,
`expand_nonce` and `render_with_nonce`.

| Input | Result |
|---|---|
| standard CSP Level 3 directive names (`default-src`, `script-src`, `script-src-elem`, `script-src-attr`, `style-src`, `style-src-elem`, `style-src-attr`, `img-src`, `font-src`, `connect-src`, `media-src`, `object-src`, `frame-src`, `child-src`, `worker-src`, `manifest-src`, `prefetch-src`, `frame-ancestors`, `base-uri`, `form-action`, `sandbox`, `report-uri`, `report-to`, `upgrade-insecure-requests`, `block-all-mixed-content`, `require-trusted-types-for`, `trusted-types`, `navigate-to`, `plugin-types`) | accepted and serialized |
| unknown directive name (`scrpt-src`, `frobnicate-src`, uppercase) | `InvalidConfig`, path names the directive (`policy.scrpt-src`) |
| JSON value string form (`"default-src": "'self' https://cdn"`) | whitespace-separated source list, as in the header syntax |
| JSON value array form (`"default-src": ["'self'", "https://cdn"]`) | one source per element; empty or non-string elements are located errors |
| keywords `'self'`, `'none'`, `'unsafe-inline'`, `'unsafe-eval'`, `'strict-dynamic'`, `'unsafe-hashes'`, `'report-sample'`, `'wasm-unsafe-eval'`, `'inline-speculation-rules'` | accepted; directive-specific keywords are only accepted where they have meaning (`'strict-dynamic'` in the script-src family) |
| nonce/hash sources `'nonce-…'`, `'sha256-…'`, `'sha384-…'`, `'sha512-…'` | accepted in the script-src and style-src families |
| `report-uri` | exactly one URL (absolute URL with a scheme or an absolute path); more or fewer values are a located error |
| `report-to` | exactly one group name (`A-Za-z0-9_-`); more or fewer values are a located error |
| `sandbox` | empty value (fully sandboxed) or CSP Level 3 sandbox tokens; unknown tokens rejected |
| `upgrade-insecure-requests`, `block-all-mixed-content` | must have no value; a value is a located error |
| `require-trusted-types-for` | exactly `'script'` |
| `trusted-types` | `*`, `'none'`, `'allow-duplicates'` or policy names; `'none'` must be alone |
| `plugin-types` | `type/subtype` MIME types |
| `frame-ancestors`, `base-uri`, `form-action`, `navigate-to` | host/scheme sources plus `'self'`/`'none'` only |
| non-ASCII, whitespace, control or `;` characters inside a source | `InvalidConfig` with the source index in the path (`policy.script-src[1]`) |
| `'none'` combined with any other source | `InvalidConfig` (browsers would ignore the `'none'`) |
| duplicate directive in a header value | `InvalidConfig` (browsers keep only the first) |
| empty policy (`{}`, empty header value) | `InvalidConfig`, `a CSP policy must declare at least one directive` |
| `to_header_value` | `dir src...; dir2 src...`, lexicographic directive order, single spaces, `; ` separators, no trailing `;`, always a valid `HeaderValue` |
| `parse_header_value(to_header_value())` | identical policy (round-trip); surrounding/duplicate whitespace and a trailing `;` are normalized |
| `{csp.nonce}` source token | kept verbatim by `to_header_value`; `requires_nonce()` is derived, never serialized |
| `generate_nonce()` | 16 bytes from the OS CSPRNG (ring `SystemRandom`), URL-safe base64 without padding (22 chars) |
| `expand_nonce(value, nonce)` | replaces whole `{csp.nonce}` tokens with `'nonce-<nonce>'`, preserving separators |
| `render_with_nonce(nonce)` | `expand_nonce(to_header_value(), nonce)` |

Tests: `crates/http/src/csp.rs` `all_standard_directives_parse_and_serialize`,
`nonce_generation_and_placeholder_expansion`,
`strict_dynamic_and_unsafe_hashes_are_supported`, `report_uri_and_report_to_are_supported`,
`invalid_directives_are_rejected_with_located_errors`,
`builder_produces_a_valid_deterministic_header_value`,
`header_round_trip_normalizes_whitespace_and_tolerates_trailing_semicolon`.

## Residual divergences

1. Caddy v2.11.9 has no CSP module at all; the generic `headers` handler emits the configured
   string verbatim, including typos and invalid directives. caddy-rs parses and validates CSP at
   load time, so an invalid policy is a located `InvalidConfig` error instead of an emitted header.
   There is no upstream behaviour to be byte-compatible with.
2. Unknown directives and invalid sources are rejected at load time. The CSP specification tells
   browsers to ignore unknown directives and malformed sources, which would let a typo silently
   weaken a policy; strictness is deliberate, and unknown `*-src` names are rejected too so no typo
   can hide behind the fallback-directive suffix rule.
3. Serialization reorders directives lexicographically and normalizes whitespace (`; ` between
   directives, single spaces between sources, no trailing `;`). The `headers` handler preserves the
   configured string exactly; a Caddy user migrating a raw CSP value may see a reordered but
   semantically identical header.
4. `{csp.nonce}` is a caddy-rs placeholder. Upstream Caddy would emit the literal `{csp.nonce}`
   token (it has no CSP nonce concept); here it is expanded per response when the caller passes a
   generated nonce.
5. `report-uri`/`report-to` require exactly one value, `'none'` must be the only source, and
   `upgrade-insecure-requests`/`block-all-mixed-content` reject any value. Browsers are lenient
   about these malformed shapes (ignoring the extra values or the directive); caddy-rs fails at
   load time instead.
6. Duplicate directives in a header value are rejected. Browsers keep the first occurrence; the
   duplicate is silently dropped upstream because the whole value is opaque.
7. The policy is request-independent: nonce generation and expansion are pure functions with no
   I/O, and the module stores no request state. Wiring the per-response nonce into the actual
   response (T-HTTP-152) is outside this task.

## Proposed register entry (program repository)

```text
## DIV-0120 — caddy-rs parses, validates and builds Content-Security-Policy values where Caddy only stages an opaque header

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no CSP middleware. A `Content-Security-Policy` response header
  is staged by the generic `headers` handler (`modules/caddyhttp/headers/headers.go`) as the
  literal configured string: no directive parsing, no source validation, no nonce generation, no
  knowledge of `{csp.nonce}`.
- caddy-rs behaviour: `crates/http/src/csp.rs` parses a policy from JSON
  (`CspPolicy::from_json`, string or array source lists) or from a header value
  (`CspPolicy::parse_header_value`) into a `BTreeMap` of directive -> source list, validates
  directive names against the CSP Level 3 set and sources against the CSP grammar at load time
  (unknown directives, unknown keywords, `'none'` combined with other sources, non-ASCII/whitespace/
  `;` in sources, duplicate header directives, `report-uri`/`report-to` with anything but one value,
  and values on valueless directives are located `InvalidConfig` errors such as
  `policy.script-src[1]`), and serializes deterministically (`to_header_value`: lexicographic
  directive order, single spaces, `; `, no trailing `;`). `{csp.nonce}` is a source token expanded
  per response by `expand_nonce` with `generate_nonce()` (16 OS-CSPRNG bytes, URL-safe base64,
  22 chars).
- Rationale: A typo or malformed source in a raw CSP value silently weakens or disables the policy
  in the browser. Load-time validation gives a located error instead, and the structured builder
  makes per-response nonces and deterministic output possible. Raw pass-through remains available
  through the generic `headers` handler for byte-exact upstream compatibility.
- Status: divergent
- Tracking: T-HTTP-151
- Test: `crates/http/src/csp.rs` `all_standard_directives_parse_and_serialize`,
  `nonce_generation_and_placeholder_expansion`,
  `strict_dynamic_and_unsafe_hashes_are_supported`, `report_uri_and_report_to_are_supported`,
  `invalid_directives_are_rejected_with_located_errors`,
  `builder_produces_a_valid_deterministic_header_value`,
  `header_round_trip_normalizes_whitespace_and_tolerates_trailing_semicolon`
```
