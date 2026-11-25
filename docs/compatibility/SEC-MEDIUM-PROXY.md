# SEC-MEDIUM-PROXY compatibility note — reverse proxy and layer4 hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note states only behaviour this implementation can point at a test for; the proposed register
entries are in the final section. Every item below is a hardening of one finding; items marked
"parity" do not differ from stock Caddy v2.11.9 and need no `stock_compat` switch.

## C1 — `trusted_proxies_strict` defaults to the right-to-left walk

### Upstream source of truth (v2.11.9)

- `modules/caddyhttp/server.go` (`determineTrustedProxy`, `trustedRealClientIP`,
  `strictUntrustedClientIP`) and the `trusted_proxies_strict` server field. With the field unset
  (`false`), Caddy takes the **left-most** valid address of the `client_ip_headers` values as the
  client IP whenever the peer is a trusted proxy. With it set, Caddy walks the values right to left
  and returns the first address outside the trusted ranges.

### The weakness

A trusted proxy APPENDS the address it saw to `X-Forwarded-For`; everything to the left was supplied
by the client. In stock non-strict mode the attacker's own left-most entry becomes `client_ip`, so
`client_ip` matchers/allow-lists, `client_ip_hash` load balancing, rate-limit identities, access
logs and the upstream PROXY-protocol source all see an address the attacker chose.

### Implemented behaviour

| Configuration | Resolution |
|---|---|
| `trusted_proxies_strict` absent, `stock_compat` unset/false | right-to-left, first address outside the trusted ranges (new default) |
| `trusted_proxies_strict` absent, `stock_compat: true` | stock left-most behaviour |
| `trusted_proxies_strict: false` (JSON) | stock left-most behaviour, in either `stock_compat` mode |
| `trusted_proxies_strict: true` / the Caddyfile `trusted_proxies_strict` flag | right-to-left in either mode |

The Caddyfile adapter only emits `trusted_proxies_strict` when the flag is written, so a Caddyfile
operator who wants the left-most behaviour uses `stock_compat true`; JSON operators may use the
explicit `false`. The strict walk is the existing implementation (skips unparsable entries, accepts
`ip:port`, `[v6]:port` and zoned forms, falls back to the direct peer when every entry is trusted
or no header is present). The setting applies to Unix-socket peers (`trusted_proxies_unix`) too.

### Tests that pin it

`crates/proxy/src/trusted_proxies.rs`:
`default_resolution_ignores_attacker_supplied_leftmost_forwarded_for` (spoofed left-most, several
header lines, trusted tail hops, garbage entries, all-trusted chain, missing/empty/garbage header,
IPv6 with port), `stock_behaviour_is_left_most_with_explicit_opt_out_or_stock_compat` (both
`stock_compat` settings, explicit true/false, Unix peers);
`crates/server/tests/http_trusted_proxies.rs`
`default_mode_ignores_the_attacker_supplied_leftmost_value`,
`explicit_non_strict_and_stock_compat_use_the_leftmost_value` (real listeners and a real
`reverse_proxy` upstream).

## Proposed register entries (program repository)

```text
## DIV-NNNN — `trusted_proxies_strict` defaults to the right-to-left client IP walk

- Area: HTTP / reverse_proxy
- Caddy behaviour: with `trusted_proxies_strict` unset, a trusted peer's client IP is the left-most
  valid address in the `client_ip_headers` values, which is client-controlled when the proxy
  appends to X-Forwarded-For.
- caddy-rs behaviour: with the field unset the right-to-left first-untrusted walk is used.
  `stock_compat true` or an explicit `trusted_proxies_strict: false` restores the stock behaviour.
- Rationale: prevents client_ip spoofing through a trusted proxy (allow-lists, client_ip_hash,
  rate-limit identity, PROXY-protocol source).
- Status: intentional divergence, secure default
- Tracking: SEC-MEDIUM-PROXY C1
- Test: `crates/proxy/src/trusted_proxies.rs`
  `default_resolution_ignores_attacker_supplied_leftmost_forwarded_for`,
  `stock_behaviour_is_left_most_with_explicit_opt_out_or_stock_compat`;
  `crates/server/tests/http_trusted_proxies.rs`
  `default_mode_ignores_the_attacker_supplied_leftmost_value`
```
