# SEC-MEDIUM-ADMIN-SERVER compatibility note — admin API and listener hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records every behaviour in this group that differs from, or tightens, stock Caddy v2.11.9, and
ends with the proposed register text.

Caveat on stock values: the Go sources (`admin.go`, `net/http`) are not available in this
environment. Stock constants quoted below (admin server `ReadTimeout` 10 s, `ReadHeaderTimeout` 5 s,
`IdleTimeout` 60 s, `MaxHeaderBytes` 64 KiB, no `WriteTimeout`; go-proxyproto's 10 s default header
timeout; `tlsHandshakeTimeout` = min of the non-zero `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`)
are from recollection of those sources and should be confirmed against `external/caddy` before the
register entries are merged.

## A1. DNS-rebinding Host check applies to every admin request

Upstream (`admin.go`, `adminHandler.ServeHTTP`): when `enforceHost` is true (a non-wildcard,
non-unix, non-remote admin listener) `checkHost` runs for every request, before and independent of
the cross-site (`Origin`/`Sec-Fetch-Mode`) mitigation, comparing `r.Host` to the allowed-origin hosts
exactly; a miss is `403 host not allowed: <host>`.

Previous caddy-rs behaviour: `OriginPolicy::check` returned early when `enforce_origin` was false
and the request had neither `Origin` nor `Sec-Fetch-Mode`, so the Host check was skipped. A
DNS-rebinding page (plain http, same-origin) could read `/config/`, `/pki/ca/local` and
`/runtime/inventory` with `Host: evil.example`. Review found three more ways past the check:
HTTP/2 prior-knowledge (h2c) requests carry only `:authority` and no `Host` header (check skipped),
an absolute-form request target was ignored in favour of the `Host` header, and an empty or
non-UTF-8 `Host` header was treated as absent.

Implemented (same in both modes; this is stock behaviour, so there is no `stock_compat` switch):

- The check runs first, unconditionally, on enforcing listeners.
- The server transport (`admin_request_headers`, `crates/server/src/listeners.rs`) resolves `Host`
  as Go sets `Request.Host`: the URI authority when the request line has one (HTTP/2 `:authority`,
  absolute-form HTTP/1), else the `Host` header; userinfo is dropped. Two `Host` headers are `400
  too many Host headers` on every admin transport (unix, TCP, remote mTLS), as in Go.
- A present-but-empty or non-UTF-8 `Host` is `403`.

Remaining intentional differences from stock (none usable by a rebinding attacker, whose `Host`
names the attacker's domain):

1. A request with no `Host` header and no URI authority passes only as HTTP/1.0 (as in Go, where it
   then has `Host == ""`) or as a synthetic in-process request; an HTTP/1.1 request without `Host`
   is `400 missing required Host header` like Go (hyper alone would have served it).
2. A port-less `Host` that names an allowed host is accepted, uniformly for `localhost`,
   `127.0.0.1` and `[::1]` (CLI/test harness convenience). Stock compares `host:port` exactly.
3. Host names compare case-insensitively (stock: exact). Origins already did.
4. Listeners configured with port 0 do not enforce the Host check (the bound port is unknown to the
   configuration), so tests and harnesses that use `127.0.0.1:0` are not covered by it. A listener
   configured with a real port does; end-to-end tests of that path bind a known port first.

Behaviour change worth knowing: clients (including test clients) that send a foreign `Host` to a
fixed-port admin listener now get `403`, as against stock Caddy. `http_runtime::admin_stop_ends_the_runtime_loop`
and `http_upstream_status::reload_swaps_the_admin_upstream_source` use a fixed admin port and fail
with `403` if their clients send `Host: example.com`; they send the listener's address instead
(verified by reverting that edit). Other harnesses using `admin.listen: 127.0.0.1:0` are unaffected.

Tests: `crates/admin/src/origin.rs` `host_check_applies_without_origin_or_sec_fetch_headers`,
`host_check_edge_cases_match_caddy_or_are_listed_differences` (bracketed IPv6 port-less, wrong
port, empty/blank/non-UTF-8 Host); `crates/server/src/listeners.rs` `admin_host_check_tests::*` on a
real listener with a known non-zero port: own Host 200 / foreign Host 403 with and without `Origin`
and `Sec-Fetch-Mode`, absolute-form target, duplicate `Host` 400, HTTP/2 `:authority` over h2c, and
`request_headers_resolve_host_like_go`.

## A2. Bounded admin request body and admin connection limits

Upstream (`admin.go`, `handleLoad`/`handleAdapt`): the request body is copied with `io.Copy` into a
buffer with no size limit, and a read failure is returned as an error. The admin `http.Server`
(local and remote) runs with `ReadTimeout` 10 s, `ReadHeaderTimeout` 5 s, `IdleTimeout` 60 s,
`MaxHeaderBytes` 64 KiB.

Previous caddy-rs behaviour: both admin listeners called `body.collect()` unbounded and turned any
read error into an empty body. They also ran with the public-server limits (`ServerLimits::default()`:
no read timeout, 1 minute header timeout, 5 minute idle timeout, no connection cap), so many trickling
connections could each hold up to 64 MiB even after a per-request cap.

Implemented (`crates/server/src/listeners.rs`, `crates/server/src/limits.rs`):

- Size: bodies above `ADMIN_MAX_BODY_BYTES` (64 MiB) are `413`; an over-cap `Content-Length` is
  rejected before any byte is read, a streamed body is cut off at the cap. `stock_compat true`
  removes the cap. A transport failure while reading is `400` in both modes, never an empty body.
- Timeouts (`ServerLimits::admin()`, both modes): `read_timeout` 10 s, first-byte/handshake budget
  5 s, idle 60 s, 64 KiB header limit, no write timeout. Effective semantics differ from a literal
  reading of those numbers:
  - The read timer is request-scoped (`ReadTimeoutScope::BodyReads`): it runs only while a request
    body is being read, like Go's per-request `ReadTimeout`. Before, the per-read timer also ran
    during the idle wait between requests and while a handler was busy with no client bytes
    expected, and hyper's header timer (5 s) closed idle keep-alive connections after 5 s; the
    first fix's "60 s idle" was really 5-10 s. Now an idle keep-alive connection lives to the 60 s
    idle timeout (test: `an_idle_keep_alive_connection_survives_past_the_read_timeout`, 12 s) and an
    in-flight request keeps the connection from being reaped. A handler running longer than 10 s
    with no client frames is therefore not torn down by `read_timeout` on the admin listeners (not
    separately tested: no slow admin handler exists to drive). Public servers are unchanged
    (DIV-0029: `read_timeout` still runs on every stalled read there, so a slow handler on a server
    with a `read_timeout` can still be cut; not changed here).
  - hyper has one header timer for both the idle wait and a request's header read, so on the admin
    listeners it is set to the idle budget: a request's headers may take up to 60 s, not stock's
    5 s (a listed divergence; the first request's first byte is still bounded to 5 s).
  - A request body must also arrive within 10 s in total (`ADMIN_BODY_DEADLINE`, `408`), Go's
    whole-request `ReadTimeout`. `stock_compat true` does not lift the 10 s deadline or the 5 s
    first-byte bound (they are stock behaviour); it lifts only the size cap and the slot limits.
- First byte: hyper's protocol sniffing starts its header timer only once a byte arrives, so the
  plaintext TCP and unix listeners explicitly drop a connection that sends nothing within 5 s
  (`await_first_byte`, which also observes shutdown). The remote mTLS listener has no such
  pre-handshake gap (the handshake budget covers it); a client that completes the handshake and
  then stays silent is cut by the idle timeout, not 5 s.
- Upload slots (caddy-rs addition, not in stock): each admin listener admits at most
  `ADMIN_MAX_CONCURRENT_BODIES` (4) concurrent requests with a body, and one peer (remote address;
  the certificate's issuer+serial on the mTLS listener; one shared principal on the unix socket) at
  most `ADMIN_MAX_BODIES_PER_PEER` (2); beyond that `503`, connection closed. A body is detected
  from the body itself (`!is_end_stream()`), not the headers, so HTTP/2 streams with DATA frames
  and no `content-length` also take a slot (they used to bypass the limit entirely). Worst-case body
  memory is 4 x 64 MiB per listener. `stock_compat true` lifts the slots together with the cap.
- Order: requests are authorised (`AdminApi::authorize`: Host/Origin on the plaintext listeners,
  access-control role on the mTLS listener) before the body is read, as stock Caddy does. A refused
  request is answered at once, takes no slot, and closes an HTTP/1 connection with its body unread,
  so a rebinding page or a role-limited certificate cannot pin slots or memory.

Tests: `admin_body_tests::*` (boundary, one over, declared length, unbounded mode, read failure,
`stock_compat` on/off); `admin_unix_tests::oversized_admin_request_bodies_are_rejected_with_413`;
`admin_limits_tests::a_silent_admin_connection_is_dropped_after_the_header_timeout` (fails before:
connection stayed open), `a_silent_admin_connection_is_dropped_by_a_forced_stop_not_after_the_budget`
(fails before), `one_peer_cannot_take_more_than_its_share_of_the_upload_slots` (fails before),
`the_global_upload_budget_still_applies_across_peers`,
`http2_streams_without_content_length_take_upload_slots` (fails before),
`an_idle_keep_alive_connection_survives_past_the_read_timeout` (fails before),
`a_refused_request_is_answered_without_reading_its_body` and the remote
`an_unauthorised_remote_request_is_refused_without_reading_its_body` (both fail before),
`a_stalled_admin_body_times_out_with_408_and_frees_its_slot`,
`slots_are_capped_per_peer_and_in_total_and_released_on_drop`;
`limits::tests::admin_limits_match_stock_caddy_admin_server`. The slot tests poll for the holders
to register (bounded) instead of sleeping.

## A3. Admin unix socket: creation window and delete-anything TOCTOU

Upstream (`admin.go`, `listenAdmin`): Caddy removes a stale socket, binds with
`net.Listen("unix", ...)`, then applies permissions; it does not check what it deletes. A
hardening that changes no valid configuration (no `stock_compat` switch; both modes identical).

Implemented (`bind_admin_unix_private`, `install_staged_socket`, `AdminSocketPath`):

- Only a socket at the configured path is replaced; a regular file, directory or symlink (including
  a dangling one) is a bind error and is left untouched (`symlink_metadata`, links never followed).
- The socket is bound inside a fresh `0700` staging directory next to the final path, set to `0600`,
  then installed: if the path is absent, with `link(2)` (fails with `EEXIST` instead of replacing,
  so a file or symlink that appears meanwhile is never overwritten); if a stale socket is there, it
  is re-`lstat`ed immediately before and `rename`d over only if it is still a socket with the inode
  seen at the start. The final name therefore never exists with umask-derived permissions.
- Liveness probe: before replacing a stale socket a `connect` is tried; success means a running
  process owns it and the bind fails with "in use by a running process" (a second caddy-rs on the
  same admin path used to silently steal the first one's socket). Only `ECONNREFUSED`/`ENOENT`
  count as stale; other probe failures are reported. `stock_compat true` replaces unconditionally,
  like stock Caddy. (A listener replaced during reload is stopped, removing its socket, before the
  new one binds, so reloads are unaffected.)
- The `link(2)` fallback to `rename` applies only to `EPERM`/`EOPNOTSUPP`/`ENOTSUP`/`ENOSYS`
  (`hard_link_unsupported`); `EACCES`, `EMLINK`, `ENOSPC` and the like are reported.
- Honest limit: the stale-socket replacement is narrowed, not eliminated. `rename` cannot be made
  conditional on the inode, and this crate denies `unsafe` (so `renameat2(RENAME_NOREPLACE)` is not
  called; no safe wrapper such as `rustix`/`nix` is a direct dependency). A swap in the microseconds
  between the re-check and the `rename` can still clobber a non-socket. The absent-path case has no
  such window. Filesystems without hard links fall back to a re-checked `rename`.
- Cleanup (`AdminSocketPath::drop`) removes the path only if it is still a socket with the device
  and inode this listener created; a regular file, symlink or another process's socket placed there
  afterwards is left alone (its `lstat`/`unlink` pair has the same narrowed-not-eliminated window).
- The staging directory name is 8 hex digits from the OS RNG (`getrandom`, retried on `EEXIST`), so
  it cannot be pre-created by a squatter in a world-writable parent. It adds 12 bytes to the bind
  path (previously about 28); when that would overflow `sun_path` but the final path fits, a
  4-digit name (8 bytes) is used instead (65 536 names: a squatter can delay, not redirect). When the bind path does not fit `sun_path` (108 bytes including the
  NUL on Linux, 104 elsewhere) the error names the configured path, the required length and the
  limit.
- Behaviour change relative to before: a stale *regular file* at the path used to be deleted and is
  now refused; a socket path within 12 bytes of the `sun_path` limit now fails to bind at startup.

Tests: `refuses_to_delete_a_regular_file_at_the_socket_path`,
`refuses_to_delete_a_symlink_or_directory_at_the_socket_path`,
`stopping_does_not_delete_a_file_or_foreign_socket_that_replaced_ours`,
`a_predictable_staging_name_cannot_block_the_bind`,
`staging_does_not_cost_much_of_the_108_byte_socket_path_budget`,
`an_over_long_staging_path_is_reported_with_the_configured_path_and_limit` (these last four fail
before), `staging_leaves_only_the_socket_behind` (deterministic: only the final socket remains, mode
`0600`, failed binds leave nothing), `replaces_a_stale_socket_and_can_rebind_after_stop`.
`watcher_never_observes_the_socket_with_wider_than_owner_permissions` polls the parent directory
from a thread while binding 200 times; it is probabilistic and can pass on the pre-fix code by
missing the microsecond window, so it is a regression probe, not proof (the creation window is
excluded by construction: the final name is only ever linked or renamed from an already-`0600`
socket).

## A4. TLS handshake and PROXY-header timeouts

Upstream (Go `net/http`, `Server.tlsHandshakeTimeout`): before the handshake the connection
deadlines are set to the smallest of the non-zero `ReadHeaderTimeout`, `ReadTimeout` and
`WriteTimeout`. Caddy defaults `read_header_timeout` to 1 minute. Caddy's `proxy_protocol` wrapper
uses go-proxyproto, which treats a zero `ReadHeaderTimeout` as 10 s.

Previous caddy-rs behaviour: no bound on the handshake (silent or partial ClientHellos pinned a task
and a descriptor); the first fix omitted `write_timeout` from the formula; an absent `timeout` on the
`proxy_protocol` wrapper made the PROXY-header read unbounded, so a silent client never reached the
handshake bound; the handshake did not observe shutdown.

Implemented (identical with and without `stock_compat`; stock behaviour):

- `ServerLimits::tls_handshake_timeout()` = min of `read_header_timeout` and the non-zero
  `read_timeout` and `write_timeout`. It bounds the HTTP/1 and HTTP/2 TLS path and the PKCS#11
  external-key path.
- The remote mTLS admin listener uses its own admin limits: `tls_handshake_timeout()` of
  `ServerLimits::admin()` = 5 s (not the public servers' 1 minute).
- `proxy_protocol` `timeout` absent or zero means 10 s (was unbounded), as one deadline over the
  whole header (was per read).
- Shutdown: a connection still in its TLS handshake or PROXY-header read is dropped immediately on
  a forced shutdown and capped at 5 s after a graceful one begins (`bounded_handshake`). Before,
  a forced shutdown waited out the runtime's 2 s drain ("listener tasks are detached") and a
  graceful drain waited for the handshake budget. Go's `Shutdown` likewise closes connections that
  never left `StateNew`.
- No tighter hardened default (for example 10 s) is applied to public servers: the server cannot
  tell an explicitly configured `read_header_timeout` from the default.

Not covered (unchanged): the L4 `tls` terminator has no handshake bound (caddy-l4 has none); QUIC
handshakes are bounded by quinn's idle timeout; `max_connections` defaults to unlimited, as in
stock Caddy; the remote admin handshake has no end-to-end timing test (the unit test pins its
budget to 5 s and the handshake path is shared with `bounded_handshake`, which has virtual-time
tests).

Tests: `crates/server/tests/http_tls.rs` `silent_tls_client_is_dropped_after_the_read_header_timeout`,
`partial_client_hello_is_dropped_after_the_budget`, `read_timeout_tightens_the_handshake_budget_like_go`,
`prompt_tls_handshake_still_succeeds_under_a_budget`,
`forced_shutdown_closes_connections_still_in_the_tls_handshake` (fails before: shutdown took 2.0 s);
`limits::tests::tls_handshake_timeout_is_the_smallest_of_read_header_read_and_write_timeout` (fails
before: write_timeout ignored); `proxy_protocol::tests::silent_client_is_dropped_after_the_default_header_timeout`
(fails before: never finishes) and `configured_timeout_overrides_the_default`;
`listeners::bounded_handshake_tests::*` (virtual time).

## Exact program-repository text to merge

> **DIV (proposed) SEC-MEDIUM-ADMIN-SERVER-A2** - Admin request bodies are capped at 64 MiB (`413`),
> and each admin listener admits at most 4 concurrent requests that carry a body, at most 2 per
> peer (`503` beyond that; HTTP/2 streams count). Requests are authorised before their body is read.
> The admin request-header read may take up to the 60 s idle budget (stock 5 s).
> Stock Caddy v2.11.9 reads `/load` and `/adapt` bodies without a limit. `stock_compat true` removes
> both bounds. A failed body read is a `400` in both modes, never an empty body. The admin servers use
> stock Caddy's timeouts in both modes, plus a 10 s total deadline for a request body (`408`) and a
> 5 s drop of a connection that sends no byte.
>
> **DIV (proposed) SEC-MEDIUM-ADMIN-SERVER-A3** - The admin unix socket is bound in a private `0700`
> staging directory with a random name and installed with `link(2)` (absent path) or a re-checked
> `rename` (stale socket), and only an existing *socket* at the configured path is replaced; a
> regular file, directory or symlink there is a bind error. Cleanup on stop removes only the socket
> this listener created. A socket that still accepts connections is not replaced ("in use by a
> running process"; `stock_compat true` replaces it unconditionally, like stock). Stock Caddy removes
> whatever is at the path.
> The stale-socket replacement is narrowed, not eliminated, against a concurrent local attacker.
>
> **DIV (proposed) SEC-MEDIUM-ADMIN-SERVER-A1** - The admin Host check matches stock Caddy except:
> a request with no Host header and no URI authority passes; a port-less Host naming an allowed host
> is accepted; host names compare case-insensitively; listeners configured with port 0 do not
> enforce it.
>
> A4 (TLS handshake bounded by the smallest of `read_header_timeout`, `read_timeout`,
> `write_timeout`; PROXY header bounded at 10 s by default; half-open handshakes observe shutdown)
> matches stock Caddy except that half-open handshakes are dropped 5 s into a graceful shutdown, and
> needs no divergence entry otherwise.
