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

### Most common breakage

CDN -> load balancer -> caddy with `trusted_proxies` listing only the load balancer: the walk now
stops at the first address outside the trusted ranges, which is the CDN edge, so `client_ip` becomes
the CDN edge IP (it used to be the left-most, client-supplied value). Add the CDN ranges to
`trusted_proxies` (so the walk continues to the real client), or restore the stock behaviour with
`stock_compat true` / an explicit `"trusted_proxies_strict": false`.

Unparsable entries: Caddy's `strictUntrustedClientIP` skips an entry that does not parse and moves
on to the next one (it does not stop and does not return an empty string); caddy-rs does the same.
This is stated from recollection of the Go source and has not been checked against the pinned
`external/caddy` tree.

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

- **HTTP engine (review fix, pre-existing bug).** `crates/http/src/matchers.rs` `IpRange` (used by
  `remote_ip`, `client_ip` and `local_ip`), `crates/http/src/auth.rs` `Cidr` (forward_auth trusted
  proxies) and `crates/http/src/acme_server.rs` `IpRange` (the ACME server's IP allow/deny policy)
  had the same cross-family `false`: on the default dual-stack listener `not remote_ip
  203.0.113.0/24` never matched an IPv4 client (deny bypass), allow lists failed closed, and the IP
  identifier `::ffff:10.0.0.1` passed an IPv4 deny policy. Each `contains` now tries the raw and the
  canonical form, and `crates/server/src/http.rs` `canonical_peer` turns a mapped peer into plain IPv4
  where it enters the request (as Go's `net` reports it), which also makes
  `{http.request.remote.host}` the dotted form. A shared helper in a common crate was not extracted
  to keep the hunks small next to concurrent edits; the four copies are now identical in behaviour.
  Tests: `ip_ranges_match_ipv4_mapped_peers`, `trusted_proxy_cidrs_match_ipv4_mapped_peers`,
  `acme_ip_ranges_match_ipv4_mapped_identifiers`, `mapped_peers_enter_the_request_as_plain_ipv4`.
- **Known deviation: `::ffff:0:0/96`.** `IpNet::parse`/`IpRange::parse` store `::ffff:0:0/96` as
  `0.0.0.0/0`, so that range matches every IPv4 address. Go's `netip.Prefix` never contains an
  unmapped IPv4 address in an IPv6 prefix, so this is NOT parity (the "parity" label above covers
  the canonical comparison of peers, not this spelling). It is kept because an operator writing the
  mapped block means "IPv4 clients" on a dual-stack listener; it is pinned by the mapped-range
  assertions in the tests above.

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

- **Only request-derived dials are guarded (review fix).** `template_is_request_derived` classifies
  the `dial` template (and, for `dynamic_upstreams`, the `name`/`service`/`proto`/`port` templates of
  each source; `multi` is guarded if any member is). A template is operator-controlled, and so
  unguarded, only if it is a literal or every placeholder is in `env.*`, `system.*`, `time.*` or
  `$VAR`; any other placeholder (`http.request.*`, `http.vars.*`, `vars.*`, `http.regexp.*`,
  `http.matchers.*`, unknown) or an unbalanced brace counts as request-derived. So
  `dynamic_upstreams { name localhost }`, Consul/Nomad SRV answering 127.0.0.1 and
  `dial localhost:{env.PORT}` keep working with the guard on. A `map` or `vars` handler that copies
  request data into `{vars.backend}` stays guarded (it is "unknown"); put its loopback targets in
  `dial_allow`. Custom `DynamicUpstreamSource` implementations default to guarded.
- **FastCGI (review fix).** FastCGI used to dial through a bare `TcpStream::connect`, so
  `transport fastcgi` + `dynamic_upstreams` with a request-derived name reached loopback/metadata
  unguarded. FastCGI dials of discovered hosts now resolve the name, check every address with the
  same `DialGuard` and connect to a checked address; unix targets need a `unix/` allow entry. Static
  placeholder dials remain rejected with FastCGI at load. Audit of every other
  `TcpStream::connect`/`UnixStream::connect` in `crates/proxy` and `crates/l4`: the HTTP clients
  (`dial_tcp`, unix connects behind `resolve_target`), DNS (resolver addresses are operator
  configuration), websocket (test code only) and the L4 proxy (fixed operator-configured upstream,
  not request-derived) are not reachable with request-derived addresses.
- **Caddyfile (review fix).** `reverse_proxy { dial_allow <ip|cidr|unix//path>... }` is a
  caddy-rs subdirective that sets the handler field (repeatable), so Caddyfile users need not use
  `stock_compat`.
- **NAT64 and 6to4 (review fix).** `64:ff9b::/96` and `2002::/16` addresses are classified by the
  embedded IPv4 address (`64:ff9b::a9fe:a9fe` and `2002:a9fe:a9fe::` are metadata).

### Design limit, stated bluntly

The guard is a deny-list of well-known dangerous ranges, not an allow-list. RFC 1918 and ULA
addresses stay reachable on purpose, so a client that controls the dial can still reach
`10.96.0.1:443` (a Kubernetes API server), `172.17.0.1:2375` (a Docker API on the bridge) or the
host's LAN address. If a request-derived dial must never be client-influenced, do not put request
data in it: map the client's choice to a fixed set of upstreams (a `map` or matchers selecting among
static `reverse_proxy` handlers) instead. `dial_allow` has no host-name entries.

A DNS name can change between the guard's resolution and the dial only inside the one `dial_tcp`
call (the same resolved list is dialled), so there is no rebind window.

### Tests that pin it

`crates/proxy/src/dial_guard.rs` (restricted/ordinary address tables, allow entries, unix prefixes,
malformed entries); `crates/proxy/src/handler.rs`
`request_derived_dials_cannot_reach_restricted_addresses_by_default`,
`dial_allow_and_stock_compat_permit_what_the_guard_denies`, `unix_expansions_need_a_dial_allow_prefix`,
`factory_enables_the_dial_guard_unless_stock_compat`, `dial_allow_is_validated_at_load`,
`dynamic_client_cache_is_bounded_and_evicts_least_recently_used`,
`dynamic_hosts_are_bounded_but_keep_the_current_pool`,
`dynamic_source_hosts_are_guarded_only_when_request_derived`,
`placeholder_dials_are_guarded_only_when_request_derived`,
`fastcgi_dynamic_hosts_go_through_the_dial_guard`; `dial_guard.rs`
`template_classification_is_conservative`, `nat64_and_6to4_forms_are_classified_by_the_embedded_ipv4`;
`client.rs` `the_dial_guard_refuses_restricted_literals_before_connecting` (asserts the guard's own
`PermissionDenied` refusal, so it does not depend on the metadata address being unreachable);
`crates/config/tests/upstream_adapt.rs` `dial_allow_adapts_to_the_handler_field_and_accumulates`.

## C4 — DNS resolver spoof resistance (parity with the DNS specification and Go's resolver)

Go's resolver (`net/dnsclient_unix.go`, used by Caddy's `transport.resolver` and the `srv`/`a`
dynamic-upstream sources) uses a random 16-bit id and checks the reply's id and question
(`checkResponse`/`checkHeader`) before accepting it. caddy-rs' hand-written resolver
(`crates/proxy/src/dns.rs`) used a sequential counter and checked only the id. Behaviour is
spec-correct, so it is unconditional (no `stock_compat` switch).

- `next_query_id` draws the id from the OS CSPRNG (`getrandom`, now a direct dependency of
  `caddy-rs-proxy`; already in `Cargo.lock`); a CSPRNG failure fails the lookup.
- `validate_response` accepts a reply only if the id matches, QR is set, exactly one question is
  echoed and its name (case-insensitive), type and class equal the query's.
- Over UDP a non-matching datagram is ignored and the wait continues until the lookup timeout; over
  TCP (and after a TC retry) a non-matching reply is an error.

Tests: `crates/proxy/src/dns.rs` `query_ids_are_not_a_predictable_sequence`,
`responses_must_echo_the_question_that_was_asked`,
`forged_udp_replies_with_the_wrong_question_are_ignored`, `a_forged_only_reply_is_never_accepted`.

## C5 — generic 502 bodies; random `cookie` secret by default

### Upstream source of truth (v2.11.9)

- `modules/caddyhttp/reverseproxy/reverseproxy.go`: a failed proxy attempt returns
  `caddyhttp.Error(502, err)`; with no error routes the client gets an empty body. caddy-rs already
  answered with the text `502 Bad Gateway`, but several paths appended the internal error
  (`502 Bad Gateway: <detail>`), reflecting the configured dial template, the attacker-controlled
  placeholder expansion and resolver/I-O errors. Unconditional fix, no `stock_compat` switch: every
  proxy-generated 502 body is exactly `502 Bad Gateway` and the detail is logged (debug-escaped) to
  stderr with the prefix `caddy-rs: reverse_proxy: 502 Bad Gateway:`.
- `modules/caddyhttp/reverseproxy/selectionpolicies.go` `CookieHashSelection`: the cookie value is
  `hex(HMAC-SHA256(secret, dial))` with `secret` defaulting to empty, so by default anyone can
  compute the cookie for any upstream and pin themselves to it.

### Implemented behaviour for the `cookie` policy

| `secret` | `stock_compat` | Cookie key |
|---|---|---|
| non-empty | either | the configured secret (unchanged) |
| absent or `""` | false (default) | a random 32-byte per-process secret (one per process, so a config reload keeps clients pinned; a restart re-pins them; configure `secret` for stickiness across restarts or instances) |
| absent or `""` | true | empty secret, stock behaviour |

Limit of the random secret: it stops a client from *computing* the cookie for an upstream it has
not been issued, but it does not let the operator prevent a client from choosing its upstream. A
client can collect the cookies that the fallback policy hands out (reconnecting until every
reachable upstream has been issued once) and replay the one it prefers. Stickiness is a routing
hint, not an access control.

The 502 detail is logged through `tracing` at debug level (not stderr), and `forward_auth`
`status_code` expansions that are not a valid status answer a fixed `invalid status code` body.

Tests: `crates/proxy/src/balancer.rs` `cookie_policy_without_a_secret_is_not_forgeable_by_default`,
`cookie_policy_keeps_the_stock_secret_under_stock_compat_and_honours_explicit_ones`;
`crates/proxy/src/handler.rs` `cookie_secret_default_follows_stock_compat`,
`refusals_do_not_reflect_the_expanded_dial_in_the_response`,
`dynamic_upstream_empty_or_invalid_expansion_is_a_located_error`.

## C6 — bounded L4 dial and FastCGI response head

- **L4 TCP proxy dial** (`crates/l4/src/handlers/proxy.rs`): `TcpStream::connect` had no deadline, so
  an upstream that never answers the SYN pinned the accepted client connection and its descriptor
  for the OS connect timeout. The dial is now bounded by `ProxyOptions::dial_timeout`, default
  `DEFAULT_DIAL_TIMEOUT` = 10 s, `with_dial_timeout(Duration::ZERO)` disables it. The 10 s default is
  this implementation's choice; I could not verify from the pinned caddy-l4 source whether its proxy
  handler applies a default dial timeout (Caddy's own `dial_timeout` convention is zero = unlimited),
  so treat the default as a hardening that stock caddy-l4 may not have. The L4 `ProxyOptions` /
  `proxy_connection` hardening is NOT reachable from runtime configuration today (the l4 crate has
  no JSON configuration for them), so it protects embedders of the crate only, and there is no
  config field to document.
- **FastCGI response head** (`crates/proxy/src/fastcgi.rs`): `read_response_head` buffered STDOUT
  until the blank line with no limit, and STDERR without limit. The head is now capped at
  `MAX_RESPONSE_HEAD_BYTES` = 1 MiB (Go's `net/textproto.ReadMIMEHeader`, used by Caddy's client,
  bounds it at the same size); exceeding it is a `FastCgiError::Protocol` (`... response headers
  exceed 1048576 bytes`) and thus a 502. STDERR kept while waiting for the head is capped at 1 MiB
  (the excess is dropped; it is only logged). Body bytes after the head are not counted. The
  head scan is incremental (new bytes plus a 3-byte overlap, so it is linear) and at most 65536
  records may be read before the head ends (`MAX_HEAD_RECORDS`): one-byte and zero-length records
  made the old scan quadratic and, for empty records, made no progress at all.

Both are unconditional (no stock_compat switch): they only reject inputs no legitimate backend
produces.

Tests: `crates/l4/src/handlers/proxy.rs`
`the_default_dial_timeout_is_ten_seconds_and_zero_disables_it`,
`a_stalled_dial_is_bounded_by_the_dial_timeout`, `dial_errors_and_successes_pass_through_the_timeout`;
`crates/proxy/src/fastcgi.rs` `a_response_head_that_never_ends_is_rejected_at_the_cap`,
`a_large_terminated_head_and_a_large_body_are_accepted`,
`stderr_collected_before_the_head_is_bounded`.

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

```text
## DIV-NNNN — `cookie` load-balancing policy defaults to a random per-process secret

- Area: reverse_proxy load balancing
- Caddy behaviour: `lb_policy cookie` without `secret` keys the HMAC with the empty string, so the
  sticky cookie is the unkeyed hash of the upstream address and can be computed by any client.
- caddy-rs behaviour: an absent or empty `secret` becomes a random per-process secret unless
  `stock_compat true`. Stickiness survives config reloads but not restarts; set `secret` for that.
  Proxy-generated 502 bodies are always the fixed text `502 Bad Gateway` (details are logged).
- Rationale: an unkeyed cookie lets a client compute the pin for any upstream without being issued
  it (a client can still replay cookies it was issued, so this is not access control); reflecting expanded dial
  strings leaks configuration and attacker-controlled text.
- Status: intentional divergence, secure default (502 bodies: unconditional)
- Tracking: SEC-MEDIUM-PROXY C5
- Test: `crates/proxy/src/balancer.rs` `cookie_policy_without_a_secret_is_not_forgeable_by_default`;
  `crates/proxy/src/handler.rs` `cookie_secret_default_follows_stock_compat`
```

```text
## DIV-NNNN — layer4 proxy dial and FastCGI response head are bounded

- Area: layer4 / reverse_proxy FastCGI
- Caddy behaviour: the layer4 proxy dial has no caddy-rs-style default deadline (unverified); Go's
  FastCGI client bounds the response head at 1 MiB via `textproto.ReadMIMEHeader`.
- caddy-rs behaviour: the L4 TCP dial times out after 10 s by default (0 disables); a FastCGI
  response head over 1 MiB, or more than 1 MiB of pre-head STDERR kept, is rejected/dropped.
- Rationale: stalled upstreams must not pin client connections; a backend must not make the proxy
  buffer without limit.
- Status: hardening (no stock_compat switch)
- Tracking: SEC-MEDIUM-PROXY C6
- Test: `crates/l4/src/handlers/proxy.rs` `a_stalled_dial_is_bounded_by_the_dial_timeout`;
  `crates/proxy/src/fastcgi.rs` `a_response_head_that_never_ends_is_rejected_at_the_cap`
```
