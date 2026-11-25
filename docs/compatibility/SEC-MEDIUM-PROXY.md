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

## C2 — IPv4-mapped IPv6 peers are canonicalised before range comparisons (parity)

### Upstream source of truth (v2.11.9)

`modules/caddyhttp/ip_range.go` / `matchers.go` (`parseIPZoneFromString`) and `server.go`
(`determineTrustedProxy`) compare addresses after `netip.Addr.Unmap()`, and caddy-rs already records
the same behaviour for the reverse-proxy peer in DIV-0098 (`handler.rs`, `to_canonical()`). This is
therefore parity, applied unconditionally (no `stock_compat` switch). Exact Go call sites are cited
from knowledge of the upstream tree and should be re-verified against the pinned `external/caddy`
checkout when the register entry is merged.

### The weakness

A dual-stack `[::]` listener reports an IPv4 client as `::ffff:a.b.c.d`. `IpRange::contains` (layer4
`ip` matcher) and `IpNet::contains` / `ServerTrustedProxies::determine` (server `trusted_proxies`)
returned `false` across address families, so a negated or deny-style `ip` matcher
(`not ip 203.0.113.0/24`) never saw the client inside its range (deny bypass), and a mapped trusted
proxy was not trusted at the server level while the handler-level check trusted it.

### Implemented behaviour

- `crates/l4/src/matchers.rs` `IpRange::contains` and `crates/proxy/src/trusted_proxies.rs`
  `IpNet::contains` compare the raw address and its `to_canonical()` form. The raw form is compared
  first so a genuine IPv6 range covering the mapped block (`::/0`) keeps matching mapped peers.
- A range written as a mapped block (`::ffff:a.b.c.d/n`, `n >= 96`) is stored as the IPv4 range
  `a.b.c.d/(n-96)`.
- `ServerTrustedProxies::determine` canonicalises the peer, and addresses parsed from forwarded
  headers are canonicalised, so the resolved client IP is the dotted IPv4 string.

HTTP-engine matchers outside this group (`crates/http/src/matchers.rs` `remote_ip`/`client_ip`,
`crates/http/src/auth.rs`, `crates/http/src/acme_server.rs`) have their own range types with the
same cross-family `false` and are not changed by this item.

### Tests that pin it

`crates/l4/src/matchers.rs` `ipv4_mapped_ipv6_peers_match_ipv4_ranges` (allow and deny, `/0`, host
route, IPv6 ranges, mapped range spelling, mixed families, matcher on a mapped peer);
`crates/proxy/src/trusted_proxies.rs` `ipv4_mapped_ipv6_addresses_are_canonicalised` (mapped peer,
mapped forwarded entries, strict and non-strict, untrusted mapped peer).

## C3 — request-derived dials: SSRF guard and bounded caches

### Upstream source of truth (v2.11.9)

`modules/caddyhttp/reverseproxy/reverseproxy.go` (`Upstream.Dial` expanded with the replacer in
`fillDialInfo`) and `upstream.go`: Caddy permits placeholders in `dial` and dials whatever the
expansion yields. This is stock behaviour; caddy-rs hardens it.

### The weakness

With `dial {http.request.header.X-Backend}:80` a client sends `X-Backend: 169.254.169.254` (cloud
metadata) or `unix//var/run/docker.sock`. Separately, every distinct expansion added a cached client
(`dynamic_clients`), a `max_conns_per_host` limiter and, for discovery, a `dynamic_hosts` entry that
were never evicted, so a client choosing the expansion could grow memory without bound.

### Implemented behaviour

- **Caches (unconditional, behaviour-preserving).** `dynamic_clients` is an LRU capped at 1024
  entries (`MAX_DYNAMIC_CLIENTS`); the least recently used pair is dropped on insert and its pool is
  released when in-flight requests finish. `dynamic_hosts` keeps only the current pool or hosts with
  requests in flight once it exceeds 1024. The per-dial `max_conns_per_host` limiter map drops
  limiters that no live connection holds once it reaches 4096.
- **Egress guard (secure default; `stock_compat true` = stock).** Clients created for request-derived
  dials (placeholder dials and `dynamic_upstreams` discoveries) carry a `DialGuard`
  (`crates/proxy/src/dial_guard.rs`). The check runs in `dial_tcp` on the **resolved** addresses, so a
  hostname resolving to a restricted address is refused too (also on the IPv4-mapped form). Refused by
  default: loopback, unspecified, link-local (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast,
  `100.64.0.0/10`, `192.0.0.192`, `fd00:ec2::/32`. RFC 1918 and ULA private ranges are NOT refused so
  ordinary internal backends keep working. Unix-socket expansions are refused unless the path lies
  below a `unix/<absolute prefix>` allow entry (a `..` component or relative path is never allowed;
  symlinks are not resolved).
- **`dial_allow` (new handler field, JSON only).** The placeholder-free allow list: IP/CIDR entries
  and `unix/<absolute path prefix>` entries. A malformed entry is a located load error
  (`...dial_allow[i]`); the field is validated in every mode.
- **`stock_compat true`** builds the handler with the guard off: stock behaviour (no check).
  Directly constructed handlers (tests/embedders) also default to the guard off, like the security
  profile; the router factories pass `!stock_compat`.

Known limits: a DNS name can change between the guard's resolution and the dial only inside the one
`dial_tcp` call (the same resolved list is dialled), so there is no rebind window; NAT64/6to4 spellings
of restricted IPv4 addresses are not recognised; `dial_allow` has no host-name entries.

### Tests that pin it

`crates/proxy/src/dial_guard.rs` (restricted/ordinary address tables, allow entries, unix prefixes,
malformed entries); `crates/proxy/src/handler.rs`
`request_derived_dials_cannot_reach_restricted_addresses_by_default`,
`dial_allow_and_stock_compat_permit_what_the_guard_denies`, `unix_expansions_need_a_dial_allow_prefix`,
`factory_enables_the_dial_guard_unless_stock_compat`, `dial_allow_is_validated_at_load`,
`dynamic_client_cache_is_bounded_and_evicts_least_recently_used`,
`dynamic_hosts_are_bounded_but_keep_the_current_pool`.

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

```text
## DIV-NNNN — IPv4-mapped IPv6 peers are matched as IPv4 by layer4 `ip` and server trusted_proxies

- Area: layer4 / HTTP trusted proxies
- Caddy behaviour: addresses are unmapped (`netip.Addr.Unmap()`) before range comparison.
- caddy-rs behaviour: the same; previously layer4 `IpRange::contains` and `IpNet::contains`
  returned false across address families, so IPv4 clients on a dual-stack listener escaped deny
  rules. Parity fix, no `stock_compat` switch.
- Status: parity (security fix)
- Tracking: SEC-MEDIUM-PROXY C2
- Test: `crates/l4/src/matchers.rs` `ipv4_mapped_ipv6_peers_match_ipv4_ranges`;
  `crates/proxy/src/trusted_proxies.rs` `ipv4_mapped_ipv6_addresses_are_canonicalised`
```

```text
## DIV-NNNN — request-derived reverse_proxy dials are checked against an egress guard

- Area: reverse_proxy
- Caddy behaviour: a placeholder in `dial` (or a request-derived dynamic-upstream name) is expanded
  and dialled without restriction, including loopback, link-local/metadata addresses and Unix
  sockets; per-expansion state is never evicted.
- caddy-rs behaviour: resolved addresses of request-derived dials in loopback, unspecified,
  link-local, multicast, broadcast, 100.64.0.0/10, 192.0.0.192 or fd00:ec2::/32, and Unix-socket
  expansions, are refused unless the handler's `dial_allow` lists them. `stock_compat true` disables
  the check. Per-expansion clients, limiters and discovered hosts are bounded (LRU / in-use only).
- Rationale: prevents SSRF to cloud metadata and local sockets through client-controlled dials and
  unbounded memory growth through distinct expansions.
- Status: intentional divergence, secure default (caches: parity-preserving)
- Tracking: SEC-MEDIUM-PROXY C3
- Test: `crates/proxy/src/handler.rs` `request_derived_dials_cannot_reach_restricted_addresses_by_default`,
  `dial_allow_and_stock_compat_permit_what_the_guard_denies`,
  `dynamic_client_cache_is_bounded_and_evicts_least_recently_used`
```
