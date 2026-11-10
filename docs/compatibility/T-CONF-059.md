# T-CONF-059 compatibility note — response matchers resolve in Caddy's declaration order

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task restores Caddy parity for response-matcher references and closes DIV-0116; the exact
replacement register text is at the end of this note.

## Defect

`reverse_proxy` collects named response matchers (`@name status ...` / `@name header ...`) and lets
`replace_status`/`handle_response` reference them. caddy-rs parsed every matcher in a pre-pass and
then resolved both reference kinds against that complete map, so

```caddyfile
:8080 {
	reverse_proxy 127.0.0.1:9000 {
		replace_status @late 404
		@late status 500
	}
}
```

adapted successfully even though Caddy refuses it. That is fail-open: the operator believes a
response policy is in force that Caddy would have refused to load, and the adapted handler silently
uses the later matcher.

The register's original wording also claimed `handle_response @late` forward references fail in
Caddy. **That is not true against the pinned oracle**: Caddy records `handle_response` segments and
resolves them in `FinalizeUnmarshalCaddyfile`, after the whole block has been read, so a forward
reference there is legal and adapts. Implementing the literal task statement for `handle_response`
would have created a new fail-closed divergence (caddy-rs refusing configuration Caddy accepts),
which is the opposite defect. The fix therefore separates the two behaviours exactly as Caddy does.

## Caddy source reference (external/caddy, tag v2.11.7 and v2.11.9)

`modules/caddyhttp/reverseproxy/caddyfile.go`:

- `UnmarshalCaddyfile` walks the block with `for d.NextBlock(0)`. A subdirective starting with `@`
  is parsed immediately into `h.responseMatchers` via `caddyhttp.ParseNamedResponseMatcher`.
- `case "replace_status"` looks the reference up **in that same loop**:
  `foundMatcher, ok := h.responseMatchers[args[0]]`; when absent it returns
  `d.Errf("no named response matcher defined with name '%s'", args[0][1:])`. Only matchers declared
  **before** the `replace_status` are visible.
- `case "handle_response"` does **not** resolve anything: it only records
  `h.handleResponseSegments = append(h.handleResponseSegments, d.NewFromNextSegment())`.
- `FinalizeUnmarshalCaddyfile` iterates `h.handleResponseSegments` and only then performs the same
  lookup (`foundMatcher, ok := h.responseMatchers[args[0]]`), after the entire block has populated
  the map. A forward reference in `handle_response` therefore resolves.

`modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go` reuses
`rpHandler.UnmarshalCaddyfile(dispenser)` + `rpHandler.FinalizeUnmarshalCaddyfile(h)`, and
`php_fastcgi`'s expansion feeds the same reverse-proxy unmarshaler, so both directives inherit the
same split.

The v2.11.7 tag has the identical two-phase code (`git show v2.11.7:.../caddyfile.go` lines 837-838
and 949), so the pinned Caddyfile documentation baseline and the v2.11.9 oracle agree.

## Rule implemented

`reverse_proxy_handler` in `crates/config/src/adapter.rs`:

- the existing pre-pass parses every response matcher into `response_matchers` (the complete set);
- the declaration walk mirrors each `@name` into `declared_response_matchers` as it passes it, so
  that map is exactly the declaration-order prefix;
- `replace_status` resolves against `declared_response_matchers`, so a forward reference fails with
  `no named response matcher defined with name '<name>'` located at the `replace_status` line;
- `handle_response` continues to resolve against the complete `response_matchers` map, matching
  Caddy's finalize phase.

`forward_auth_handler` and `build_php_fastcgi_routes` pass their block items through to
`reverse_proxy_handler`, so the rule applies to all three directives without separate code.

An unknown matcher (never declared in the block) still fails for both kinds, as before.

## Oracle verification (Caddy v2.11.9 h1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE)

`replace_status` forward reference — Caddy exits 1 and logs (stderr) its JSON error; caddy-rs returns
the located `config.invalid` error:

| directive | oracle stderr (level=error) | caddy-rs error |
|---|---|---|
| `reverse_proxy` | `parsing caddyfile tokens for 'reverse_proxy': no named response matcher defined with name 'late', at rp_replace_forward.caddyfile:3` | "invalid configuration at `Caddyfile line 3`: no named response matcher defined with name 'late'" |
| `forward_auth` (with `uri /auth`) | `parsing caddyfile tokens for 'forward_auth': no named response matcher defined with name 'late', at fa_replace_forward.caddyfile:4` | "invalid configuration at `Caddyfile line 4`: no named response matcher defined with name 'late'" |
| `php_fastcgi` | `parsing caddyfile tokens for 'php_fastcgi': no named response matcher defined with name 'late', at php_replace_forward.caddyfile:3` | "invalid configuration at `Caddyfile line 3`: no named response matcher defined with name 'late'" |

`handle_response` forward reference — Caddy exits 0 and adapts; caddy-rs adapts to the same JSON
(the matcher is applied to the deferred handler):

| directive | oracle | caddy-rs |
|---|---|---|
| `reverse_proxy` | exit 0, `handle_response[0].match.status_code = [500]` | same JSON |
| `forward_auth` | exit 0, canonical 2xx entry then the 500 entry with the forward-declared matcher | same JSON |
| `php_fastcgi` | exit 0, FastCGI expansion with the 500 entry carrying the forward-declared matcher | same JSON |

Valid declaration order (matcher before its `replace_status`/`handle_response` use) adapts
byte-identically to the oracle for all three directives; the six oracle `.json` outputs are checked
in as golden fixtures. Evidence artifacts: `.scratch/logs/t-conf-059/` (Caddyfiles, oracle JSON,
oracle stderr, full test log).

## Tests

Golden fixtures (`crates/config/tests/fixtures/local/`, each `.caddyfile` + oracle-exact `.json`,
exercised by `local_adapt::local_fixtures_have_exact_output_and_validate`):

- `reverse_proxy_response_matcher_declared_before_use`
- `reverse_proxy_handle_response_forward_reference`
- `forward_auth_response_matcher_declared_before_use`
- `forward_auth_handle_response_forward_reference`
- `php_fastcgi_response_matcher_declared_before_use`
- `php_fastcgi_handle_response_forward_reference`

Named assertions (`crates/config/tests/response_matcher_order_adapt.rs`, 6 tests):

- `replace_status_forward_reference_is_rejected_for_reverse_proxy`
- `replace_status_forward_reference_is_rejected_for_forward_auth`
- `replace_status_forward_reference_is_rejected_for_php_fastcgi`
- `only_the_forward_reference_is_rejected` (earlier matcher accepted, error exactly at the forward
  reference)
- `handle_response_forward_reference_adapts_like_caddy`
- `valid_declaration_order_matches_the_oracle_fixture`

The T-CONF-058 ordering tests (`crates/config/tests/replace_status_order_adapt.rs`, 5 tests) and the
upstream fixture sweep (`upstream_adapt::all_curated_upstream_fixtures_match_caddy`) pass unchanged.

`cargo test --offline --locked -p caddy-rs-config`: **346 passed, 0 failed** across 23 test binaries
(6 new); `cargo fmt --all -- --check` clean.

## Divergence status

DIV-0116 becomes `fixed`. No other config surface is affected: `forward_auth` and `php_fastcgi` share
the reverse-proxy path, `intercept` is not adapted by this build, and no upstream `caddyfile_adapt`
fixture declares a `replace_status` forward reference. `ADAPT-CONFORMANCE.md` is unaffected because
no upstream fixture changes output.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md` — replace the whole DIV-0116 entry with:

> ## DIV-0116 — Response matchers resolve in Caddy's declaration order
> - Status: fixed
> - Area: Configuration / adapter
> - Caddy behaviour: `reverse_proxy`/`forward_auth`/`php_fastcgi` resolve the two response-matcher reference kinds in different phases. `replace_status` is appended to `Handler.HandleResponse` while `UnmarshalCaddyfile` walks the block, so it resolves its named matcher immediately and a reference to a matcher declared later fails adaptation with `no named response matcher defined with name '<name>'` (exit 1, located at the `replace_status` line). `handle_response` segments are only recorded and resolved in `FinalizeUnmarshalCaddyfile`, after the whole block is parsed, so a `handle_response` may reference a matcher declared later in the same block and adapts.
> - caddy-rs behaviour: matches Caddy. A `replace_status` forward reference is a located `config.invalid` error naming the `replace_status` line and the matcher ("no named response matcher defined with name '<name>'"); a matcher declared before its use, and a `handle_response` forward reference, adapt byte-identically to Caddy v2.11.9.
> - Rationale: accepting configuration the oracle rejects is fail-open, because the operator believes a response policy is in force that Caddy would have refused to load. Resolving each reference in Caddy's phase keeps the adapted JSON exact without narrowing valid configuration.
> - Tracking: T-CONF-059
> - Test: `crates/config/tests/response_matcher_order_adapt.rs` (6 tests: forward `replace_status` rejected for `reverse_proxy`/`forward_auth`/`php_fastcgi`, forward `handle_response` accepted, oracle-exact valid order), golden fixtures `reverse_proxy_response_matcher_declared_before_use`, `reverse_proxy_handle_response_forward_reference`, `forward_auth_response_matcher_declared_before_use`, `forward_auth_handle_response_forward_reference`, `php_fastcgi_response_matcher_declared_before_use`, `php_fastcgi_handle_response_forward_reference` via `local_fixtures_have_exact_output_and_validate`.
