# Server egress TCP connect sites (ADR-0043 §1)

ADR-0043 §1 says "one helper owns all server egress TCP creation". This file is the committed
exemption list T-PROXY-065's acceptance requires: every `TcpStream::connect` / `TcpSocket::new*`
under `crates/proxy/src` and `crates/http/src` that is **not** inside the helper, and why.

The list is enforced by `every_egress_connect_is_the_helper_or_a_named_exemption` in
`crates/proxy/src/client.rs`, which parses the source rather than trusting this prose: a new
connect site that is not named here fails the test.

## The helper

`connect_address` at `crates/proxy/src/client.rs` is the only place that creates a server-egress
TCP socket. It implements all three cases of ADR-0043 §1 (no local address; port-0 local address
with `IP_BIND_ADDRESS_NO_PORT`; explicit-port local address with `SO_REUSEADDR`).

## Exemptions

Each exempt site carries the marker `ADR-0043 egress helper` in a comment directly above the dial,
and the test requires **both** that marker and a row here. Requiring only the file name was the
first version of the test and it was wrong: it exempted *every* dial in an already-exempt file, so a
new `TcpStream::connect` added to `dns.rs` passed. That is measured, not assumed — the file-only
variant was run against a smuggled dial and it passed.

| Site | Why it is not the helper |
|---|---|
| `crates/proxy/src/client.rs` — the helper's own body | This *is* the helper. Recognised by byte range, not by an exemption. |
| `crates/proxy/src/websocket.rs:290` | Inside `#[cfg(test)] mod tests` (`tcp_pair()`): a test harness connecting two ends of a loopback pair. Not server egress. |
| `crates/http/src/radar_client.rs:642` | Radar polling. `RadarClient` carries no local-address configuration at all, so the ADR-0043 defect (a *pinned* source address forcing `bind()` to reserve a unique 2-tuple) is **unreachable** here. Routing it through the helper would produce `connect_address(dest, None)`, whose first branch is literally `TcpStream::connect(dest).await` — a byte-identical call that changes no behaviour and no test could distinguish. Per ADR-0043 §5 ("no silent degradation ... a located error or a documented divergence with a test"), a no-op conversion that only satisfies a textual grep is worse than a named exemption. |
| `crates/http/src/radar_store.rs:460` | Same reasoning as `radar_client.rs`: no local-address configuration, defect unreachable. Named in ADR-0043's inventory as "healthy (vanilla)". |
| `crates/proxy/src/dns.rs` — TCP fallback | The resolver's TCP path binds no source address; it dials the configured `ResolverAddress` directly. Defect unreachable, same reasoning. Tagged `T-PROXY-065` in-file. |
| `crates/proxy/src/fastcgi.rs:623` | `FastCgiTransport` has no local-address field, so the defect is unreachable. Tagged `T-PROXY-065` in-file. |

## Sites that moved (the actual fix)

| Site | Why it moved |
|---|---|
| `crates/proxy/src/client.rs` `connect_address` | The one site that honours `transport.local_address`. This is the only place in the program where the DIV-0153 defect was reachable; T-PROXY-064 built the fix here and T-PROXY-065 proved it behaviourally. |
| `crates/proxy/src/client.rs` `race_connect` call sites | They call `connect_address` directly, so both the racing and the single-attempt path go through the helper. |

## What is deliberately *not* claimed

The set of exemptions above is not "these sites are healthy, nothing to see". It is "the defect
ADR-0043 describes cannot be reached from them, because none of them lets an operator pin a source
address". If a future change gives any of them a `local_address` option, that row stops being an
exemption and the site must move into the helper in the same change.
