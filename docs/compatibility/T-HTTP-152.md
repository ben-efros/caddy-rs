# T-HTTP-152 compatibility note — `security_headers` route integration

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task wires the T-HTTP-150 middleware (`crates/http/src/security_headers.rs`) into the route engine.
The note below states only behaviour this implementation can point at a test for; the proposed
register entry is at the end.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- Caddy v2.11.9 has **no** `security_headers` HTTP handler module. It is a caddy-rs extension, like
  the T-HTTP-150 middleware it integrates. The comparable upstream reference is the generic
  `headers` handler (`modules/caddyhttp/headers/headers.go`), whose two behaviours are reused here:
  response header mutations are staged by middleware and merged onto the response before it is
  written (caddy-rs T-ROUTE-011 response middleware staging), and header values are expanded at
  request time through `caddy.Replacer` with `ReplaceKnown` semantics — known placeholders are
  substituted, unknown placeholders are left verbatim (`replacer.go`).
- `modules/caddyhttp/staticresp.go` fills in an implicit `Content-Type` only when the response
  header map does not already carry one. caddy-rs keeps that interaction because the staged map is
  the last writer at merge time.
- Real Caddy's top-level empty handler answers an unmatched request with `200 OK` and an empty
  body (caddy-rs DIV-0068), not a 404.

## Implemented behaviour

`SecurityHeadersConfig::from_json(value, path)` parses the handler object; `Router::build_handler`
registers `{"handler": "security_headers", ...}` exactly like `{"handler": "headers", ...}`. The
configuration is validated through `SecurityHeaders::new`, so an invalid HSTS configuration is
rejected when the router is built (load time) with the JSON path of the offending field.

| Key | Type | Emitted header |
|---|---|---|
| `frame_options` | string or `false` | `X-Frame-Options` (default `DENY`) |
| `content_type_options` | string or `false` | `X-Content-Type-Options` (default `nosniff`) |
| `referrer_policy` | string or `false` | `Referrer-Policy` (default `strict-origin-when-cross-origin`) |
| `content_security_policy` | string or `false` | `Content-Security-Policy` (opt-in) |
| `permissions_policy` | string or `false` | `Permissions-Policy` (opt-in) |
| `strict_transport_security` | object or `false` | `Strict-Transport-Security` (opt-in) |

`strict_transport_security` is `{"max_age": <u64>, "include_subdomains": <bool>,
"preload": <bool>}`; `max_age` is required when the object is present and the booleans default to
`false`. A string is the emitted value; `false` or `"false"` suppresses the header. Unknown keys at
either level are a located `InvalidConfig` naming `<json path>.<field>`.

Placeholder expansion happens at request time in every configured value, with the same
`ReplaceKnown` semantics as the `headers` handler (for example `{http.request.host}` in a
`content_security_policy`; unknown placeholders stay visible).

Ordering follows the T-ROUTE-011 staging model and route evaluation order:

| Route shape | Precedence |
|---|---|
| Several `security_headers`/`headers` handlers in one chain | the last handler to stage a header wins for that name |
| Global (catch-all) route + a per-route handler | the per-route handler runs later, so its configured names win; opt-in headers only the global route configured are inherited |
| Parent route + `subroute` that continues the chain | the staged map is shared, so the subroute configuration wins and inherits what it does not configure; the three defaulted headers are re-asserted by every handler |
| `subroute` that itself produces the response | the nested router merges its own staged map first; the outer level then applies its unchanged staged map last, so the outer value wins for a same-named header |
| Handler sets a response header explicitly | the staged merge is the last writer, so the middleware value replaces it (this is what lets `headers.response.set` override `static_response`'s implicit `Content-Type`) |

Responses that short-circuit before the `security_headers` handler runs are not decorated: a request
that matches no route, a matcher error, or an `error` handler that fails earlier in the chain never
stages these headers. `security_headers` inside the `handle_errors` routes is the explicit opt-in
that decorates error responses.

Tests (in-file unit tests): `crates/http/src/security_headers.rs`
`from_json_applies_secure_defaults_and_overrides`, `from_json_false_suppresses_defaulted_and_opt_in_headers`,
`from_json_rejects_unknown_keys_with_located_paths`, `from_json_rejects_invalid_hsts_with_located_path`,
`stage_overrides_staged_values_and_expands_placeholders`, `existing_response_header_is_not_overwritten`;
`crates/http/src/router.rs` `security_headers_apply_to_any_handler_response`,
`security_headers_apply_to_response_produced_in_subroute`,
`per_route_security_headers_override_global_defaults`,
`subroute_security_headers_inherit_and_override_parent`,
`security_headers_expand_placeholders_in_values`,
`deeper_middleware_configuration_overrides_outer_security_default`,
`internal_error_responses_are_not_decorated_unless_configured`.

## Residual divergences

1. `security_headers` is a caddy-rs extension with no Caddy v2.11.9 module; a configuration using it
   has no oracle equivalent. This is the advertised extension surface, not a parity gap.
2. When a `subroute` both configures `security_headers` and produces the response, the outer route's
   unchanged staged map is applied after the nested router's merge (T-ROUTE-011 merge order), so the
   outer value wins. Caddy's `headers` handler writes into the shared response writer at request
   time, where the deeper handler runs later and wins. The two shapes are documented and tested; a
   route that wants the deeper configuration to win must let the `subroute` continue the chain.
3. The staged merge replaces a same-named response header instead of appending a second value, while
   Go's `http.Header.Add` can leave two values (Caddy) when a `static_response` `headers` entry
   collides with a middleware value; caddy-rs responses are single-valued for these headers.
4. An unmatched request terminates as Caddy's empty `200` (DIV-0068), not a 404, so the
   "internal error responses are not decorated" test uses a `handle_errors` 404 produced by an
   `error` handler that fails before the middleware runs.
5. Placeholder expansion errors (a placeholder value that is not a valid header value) surface as a
   located `InvalidConfig` naming the header at request time; Caddy's `headers` handler fails the
   request from the replacer instead.

## Proposed register entry (program repository)

```text
## DIV-NNNN — `security_headers` is a caddy-rs extension whose staged headers follow route-order precedence

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no `security_headers` handler. Its generic `headers` handler
  writes response headers into the shared response writer at request time, so a handler that runs
  later (including inside a `subroute`) overwrites an earlier value; an unmatched request ends as
  an empty 200.
- caddy-rs behaviour: `security_headers` configures secure defaults (`X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`) plus opt-in
  CSP/HSTS/Permissions-Policy per handler object. Values are staged into the request's pending
  response headers, expanded with ReplaceKnown at request time, and merged onto the response by the
  router. Within one chain the last staging handler wins; a continuing `subroute` shares the staged
  map and wins over its parent; a `subroute` that responds is merged at its own level before the
  outer merged map, so the outer value wins there. Error responses produced before the handler runs
  are not decorated; `security_headers` in `handle_errors` is the explicit opt-in.
- Rationale: The handler is an advertised caddy-rs extension, not a Caddy module; staging through
  T-ROUTE-011 keeps it consistent with the generic `headers` handler and lets the route engine
  compose per-route, per-subroute and global configurations without a second header pipeline.
- Status: extension (residual divergence 2 documents the subroute-that-responds ordering)
- Tracking: T-HTTP-152
- Test: `crates/http/src/router.rs` `security_headers_apply_to_any_handler_response`,
  `per_route_security_headers_override_global_defaults`,
  `subroute_security_headers_inherit_and_override_parent`,
  `security_headers_expand_placeholders_in_values`,
  `internal_error_responses_are_not_decorated_unless_configured`
```
