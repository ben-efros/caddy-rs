# SEC-MEDIUM-ADMIN-SERVER compatibility note — admin API and listener hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records every behaviour in this group that differs from, or tightens, stock Caddy v2.11.9, and
ends with the proposed register text.

## A1. DNS-rebinding Host check applies to every admin request

Upstream (`admin.go`, `adminHandler.ServeHTTP`): when `enforceHost` is true (a non-wildcard,
non-unix, non-remote admin listener) `checkHost` runs for every request, before and independent of
the cross-site (`Origin`/`Sec-Fetch-Mode`) mitigation, and a Host that is not in the allowed-origin
host list gets `403 host not allowed: <host>`.

Previous caddy-rs behaviour: `OriginPolicy::check` returned early when `enforce_origin` was false
and the request had neither `Origin` nor `Sec-Fetch-Mode`, so the Host check was skipped. A
DNS-rebinding page (attacker name rebound to 127.0.0.1, plain http so no `Sec-Fetch-*`, same-origin
so no `Origin`) could read `/config/`, `/pki/ca/local` and `/runtime/inventory` with
`Host: evil.example`.

Implemented behaviour: the Host check runs first, unconditionally, on enforcing listeners. This is
stock Caddy's behaviour, so there is no `stock_compat` switch (both modes behave identically).
Retained, documented relaxations (unchanged): a request with no `Host` header at all (synthetic
unit-test requests) and a port-less Host that matches an allowed host's host part (`Host: localhost`)
are accepted; neither is usable by a rebinding attacker, whose Host names the attacker's domain.

Tests: `crates/admin/src/origin.rs`
`host_check_applies_without_origin_or_sec_fetch_headers` (foreign Host with/without port rejected
with 403 and Caddy's message; `localhost`, `127.0.0.1`, `[::1]`, mixed case, port-less and Host-less
accepted; unix and wildcard listeners still unenforced).

## A2. Bounded admin request body

Upstream (`admin.go`, `handleLoad`/`handleAdapt`): the request body is copied with `io.Copy` into a
buffer with no size limit, and a read failure is returned as an error to the client.

Previous caddy-rs behaviour: the plaintext/unix and the remote mTLS admin listeners both called
`body.collect()` unbounded (multi-gigabyte `POST /load` => out-of-memory) and turned any read error
into an empty body, so `/load` ran against a silently truncated request.

Implemented behaviour (`crates/server/src/listeners.rs`, `read_admin_body`):

- Default (`stock_compat` false/absent): bodies above `ADMIN_MAX_BODY_BYTES` (64 MiB) are answered
  `413` with Caddy's `{"error": ...}` shape. An over-cap `Content-Length` is rejected before any
  byte is read; a streamed (chunked) body is cut off at the cap.
- `stock_compat true` on the active generation: no cap (stock behaviour).
- In both modes a transport failure while reading the body is `400`, never an empty body. Stock
  Caddy also surfaces read errors, so this is not a stock divergence.
- The cap is a constant; no admin config field was added (there is no natural place in Caddy's
  `admin` object, and a caddy-rs-only field would need its own validation surface).

Tests: `crates/server/src/listeners.rs` `admin_body_tests::*` (boundary inclusive at the limit, one
byte over, declared `Content-Length` over the cap, malformed `Content-Length`, unbounded mode,
read failure with and without a cap, `stock_compat` on/off via a loaded generation) and
`admin_unix_tests::oversized_admin_request_bodies_are_rejected_with_413` (end to end over the unix
admin socket).

## A3. Admin unix socket: creation window and delete-anything TOCTOU

Upstream (`admin.go`, `unixlistener`/`listenAdmin`): Caddy removes a stale socket and binds with
`net.Listen("unix", ...)`, then applies the configured `0200`-style permissions afterwards; it does
not check what it deletes. That is the same weakness, so this is a hardening that does not change
any valid configuration's behaviour (no `stock_compat` switch; both modes behave identically).

Implemented (`bind_admin_unix_private`, `crates/server/src/listeners.rs`):

- Only a socket at the configured path is replaced. A regular file, directory or symlink (including
  a dangling one) is a located bind error (`... exists and is not a socket`) and is left untouched;
  the check uses `symlink_metadata`, so links are never followed.
- The socket is bound inside a fresh `0700` staging directory next to the final path, set to
  `0600`, and atomically renamed into place, so the final name never exists with umask-derived
  permissions. The staging directory is removed on success and on failure.
- Behaviour change relative to before: a stale *regular file* at the path used to be silently
  deleted and is now refused. The staging name adds about 27 bytes to the bind path, so a socket
  path within that margin of the 108-byte `sun_path` limit now fails to bind at startup.

Tests: `admin_unix_tests::refuses_to_delete_a_regular_file_at_the_socket_path`,
`refuses_to_delete_a_symlink_or_directory_at_the_socket_path`,
`socket_is_never_visible_with_wider_than_owner_permissions` (staging directory cleaned on success
and failure, final mode `0600`), `replaces_a_stale_socket_and_can_rebind_after_stop` (replaces the
former test that planted a regular file).
