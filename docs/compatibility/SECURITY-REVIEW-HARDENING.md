# Security-review hardening — compatibility note

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation changes. This
note records, in the repository convention (see `T-HTTP-151.md`), every place the changes from the
internal security review differ from stock Caddy, with a **proposed** register entry for each. Ids
are not assigned here; the register owner assigns `DIV-xxxx` when the entries are accepted.

## Upstream sources compared

Every statement about stock Caddy below was checked against a read-only checkout of the pinned
upstream, not recalled from memory:

| Source | Version | Commit |
|---|---|---|
| `github.com/caddyserver/caddy` | `v2.11.9` | `0d98caea58f794f88e709b1bef2880996a471bca` |
| `github.com/caddyserver/certmagic` (Caddy's `go.mod` requirement) | `v0.25.6` | tag |
| `github.com/quic-go/quic-go` (Caddy's `go.mod` requirement) | `v0.63.0` | tag |
| Go standard library `internal/filepathlite` (`go 1.26.0` per Caddy's `go.mod`) | `go1.26.0` | tag |

File and line references below are to those trees. Statements about caddy-rs are each backed by the
named test. Where the upstream behaviour could not be reproduced here (nothing was *run*; the
comparison is by reading the source) the entry says so.

## 1. Default ceiling and process-wide budget for buffered request bodies

**Stock Caddy.**

- There is no default request-body limit. The only limit is the operator's `request_body` handler
  `max_size` (`modules/caddyhttp/requestbody/caddyfile.go:36`).
- `reverse_proxy` buffers a request body only when `request_buffers` is non-zero
  (`modules/caddyhttp/reverseproxy/reverseproxy.go:168`, `:841`), and then only "up to this size";
  `-1` means unlimited and logs an `UNLIMITED BUFFERING` warning (`:295`). The remainder of a larger
  body is not rejected: `bufferedBody` returns the buffered prefix followed by the rest of the
  original stream (`io.MultiReader(buf, originalBody)`, `:1588-1613`).
- **Retries do not buffer.** The retry code states that "users can buffer the entire request body to
  allow the request to be resent" (`:503`); a body that was not buffered is simply not replayable.
- The FastCGI transport's default is a **4096-byte** request buffer, used to learn a `Content-Length`
  (`modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go:158`).
- `forward_auth` always rewrites the sub-request to `GET`, "which implicitly turns off sending the
  incoming request's body" (`modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go:99-103`), so it
  does not buffer the client's body.

**caddy-rs.** Request bodies stream to handlers on HTTP/1.1, HTTP/2 and HTTP/3. A body is buffered
only when a handler needs all of it — `reverse_proxy` `retries`/`try_duration` (**a pre-existing
divergence**: stock Caddy does not auto-buffer for retries), FastCGI (whole body, not 4096 bytes),
`handle_response`/`forward_auth` (whole body, though stock sends the auth sub-request no body) — or
when `max_request_body_size` is set and the client sends a chunked body without `Content-Length`.
The decision is per server (router-wide). Buffered bodies are now bounded even with no configured
limit:

- per request: 128 MiB (`DEFAULT_BUFFERED_BODY_LIMIT`); over it the response is `413`. A configured
  `max_request_body_size` larger than 128 MiB raises the ceiling. A declared `Content-Length` over
  the ceiling is refused with `413` before any byte is read.
- across requests: a 1 GiB process-wide budget (`BUFFERED_BODY_BUDGET_BYTES`). Each buffered body
  reserves twice its size until its response is produced; when the budget is exhausted a new
  buffered request is answered `503 Service Unavailable`.

**Why.** Without them one unauthenticated client (or one HTTP/2 connection multiplexing hundreds of
streams) can exhaust server memory. Measured on the unfixed build: 24 streams of 127 MiB on one h2c
connection took server RSS from 11 MiB to about 6.2 GiB. Stock Caddy has the same exposure when an
operator enables `request_buffers -1`, but it is opt-in there; here the buffering is implicit.

**Consequence.** Because the buffering decision is per server, one buffering route (for example a
`forward_auth`) makes every route on that server buffered and subject to the ceiling, so an upload
larger than the ceiling fails there even if its own route would stream. Keep large-upload endpoints
on a server block with no buffering handler. Making the decision per matched route would also
remove the pre-existing auto-buffering divergence for `forward_auth`; it is not done here.

**Tests.** `crates/server/tests/http_limits.rs`
(`buffered_request_body_is_capped_even_without_a_configured_limit`,
`configured_limit_overrides_the_default_buffering_cap`,
`declared_length_over_the_buffering_ceiling_is_refused_up_front`),
`crates/server/tests/http_buffer_budget.rs`
(`concurrent_buffered_bodies_exhaust_a_process_wide_budget_with_503`),
`crates/server/src/limits.rs` (`budget_tests`), and for HTTP/3
`crates/server/tests/http3.rs::http3_buffering_route_keeps_the_buffered_ceiling`.

**Proposed register entry.** *caddy-rs bounds buffered request bodies by default (128 MiB per
request, 1 GiB process-wide, `413`/`503`); stock Caddy imposes no default bound and does not buffer
for retries or `forward_auth`.* Class: hardening extension; user-visible; the per-request ceiling is
raised by `max_request_body_size`, the process-wide budget is not configurable in this release.

## 2. HTTP/3 request bodies stream

**Stock Caddy.** quic-go serves **every request stream in its own goroutine**
(`http3/server.go:517-585`, `wg.Go(func() { hconn.HandleRequestStream(str) })`), and the handler reads
the request body from the stream as it consumes it. HTTP/3 therefore streams large uploads and
handles requests on one connection concurrently.

**caddy-rs, before.** HTTP/3 always collected the entire request body in memory before routing, so a
large upload either exhausted memory or (after item 1) failed with `413` at 128 MiB, unlike
HTTP/1.1 and HTTP/2 here and unlike stock Caddy.

**caddy-rs, now.** HTTP/3 uses the same rule as HTTP/1.1 and HTTP/2: the body streams unless a
handler needs it buffered (item 1). The QUIC request stream is split; a reader task feeds a
4-chunk bounded channel, so a slow handler applies QUIC flow-control backpressure and memory per
upload is a few chunks regardless of size. `max_request_body_size` is enforced lazily as the body is
read, and a declared `Content-Length` over it is refused up front. Closing the request stops the
reader and drops the stream, which makes quinn tell the client to stop sending (see the
STOP_SENDING note below).

**Request-body integrity and timeouts on HTTP/3 (aligned with stock).**

- *Content-Length.* quic-go's request body enforces the declared length and resets the stream with
  `H3_MESSAGE_ERROR` when more data arrives than declared (`http3/body.go:44-57`). The h3 crate used
  here does not, so caddy-rs now counts the bytes: more than declared, or a stream that ends short
  of the declared length, fails the body and the client receives `400` (buffered path and streaming
  path alike). Unlike quic-go, the stream is not reset with `H3_MESSAGE_ERROR` (see STOP_SENDING).
- *Stalled uploads.* Stock Caddy aborts a request-body read that stalls for `read_idle_timeout`
  (default 1 minute, negative disables; `modules/caddyhttp/server.go:80`, enforced at `:593`). caddy-rs
  validated that field but never enforced it. It is now parsed into `ServerLimits.read_idle_timeout`
  with the same semantics and applied to HTTP/3 request bodies (together with `read_timeout`; the
  shorter wins). On expiry the client gets `408`.
  HTTP/1.1 and HTTP/2 request bodies still rely on `read_timeout` only (existing `DIV-0029`); making
  `read_idle_timeout` effective there is not done here.
- *Client is never told success for a failed upload.* If the body fails mid-stream (stall, length
  mismatch, broken stream) the handler's answer is replaced with `400`/`408`. This exists because
  hyper's HTTP/1 client ends an upstream request whose body errored with a normal terminating chunk,
  so a proxy upstream can see the truncated upload as complete and answer `200`. The upstream may
  therefore still have processed the short body; only the client-visible result is corrected. This
  is a property of the proxy's HTTP/1 upstream path, not specific to HTTP/3, and is **not fixed**
  here. Stock Caddy's reverse proxy sends through Go's HTTP transport, which fails the upstream
  request when the request body reader returns an error; that Go behaviour was not re-read in the
  pinned sources, so this is recorded as a suspected divergence, not a confirmed one.
- *Malformed `Content-Length`.* Several values, a sign, or a list whose values disagree are refused
  with `400` before any body is read (RFC 9114 section 4.1.2); equal repeated values count as one.
  The length check only sees data that arrives while the handler is still reading: a handler that
  finishes after exactly the declared number of bytes never observes surplus data sent later.
- *STOP_SENDING / reset codes (divergence).* When a request ends before its upload does, the stream
  is dropped and quinn tells the client to stop sending with application error code `0`. quic-go
  uses specific codes (`H3_MESSAGE_ERROR` on a length violation; RFC 9114 section 4.1 says
  `H3_NO_ERROR` SHOULD be used for an early answer). caddy-rs cannot send them: h3-quinn's
  `RecvStream::stop_sending` (and `recv_id`) `unwrap()` an `Option` that is `None` whenever a read is
  in flight, and h3 also reads ahead after a data frame, so calling them panics intermittently — a
  first version did, and with the `panic = "abort"` release profile that would let any client kill
  the process. Reproduced as an intermittent panic in a full parallel test run, with a backtrace
  into the body reader. The HTTP status the client sees (`400`/`408`) is unaffected. A unit test
  asserts no code in `listeners.rs` calls those methods (the crash is timing dependent and a
  regression test for it would be flaky), and a panic recorder fails the HTTP/3 tests if a spawned
  task panics. Sending the right codes needs an h3-quinn fix or a wrapper around the receive stream.
- *Late failures.* The "never tell the client success" replacement happens once, when the response
  headers are produced. A handler or upstream that sends response headers before the upload fails
  (full-duplex, or an early answer while the client keeps uploading) keeps its status; a later
  stall is not reported to the client. Trailers on a request body are discarded (as before).

**Concurrency and shutdown on HTTP/3 (aligned with stock).** Requests on one QUIC connection used
to be handled inline, one at a time, in the connection loop; a long or stalled request delayed every
other request on that connection and the loop did not observe shutdown or force signals while a
request ran. Each request stream now runs in its own task (quic-go: `wg.Go(HandleRequestStream)`).
Graceful shutdown now drains. Each connection sends GOAWAY (`max_requests = 0`) and keeps polling
`accept()` so a stream the client opened past it is rejected rather than left hanging, then waits
for its in-flight requests; a force signal (second signal, or the grace period ending) aborts them.
The listener keeps its endpoint open in a **detached** task that refuses new connections outright
(clients fail fast instead of timing out on the handshake) until every connection has finished, then
closes it. The UDP listener used to close the whole endpoint the moment a graceful shutdown began,
which cut off every in-flight upload and download (HTTP/1 and HTTP/2 already drained). Because the
drain is detached, a reload that removes a UDP listener applies immediately and does not wait for
requests still in flight on it (a first version joined the drain and blocked the reload, and the
shutdown/force signals, behind one stalled upload). The removed listener's UDP socket stays bound
until its drain ends; a replacement listener on the same UDP port during that window would conflict
(new listeners bind before old ones are removed, so this already applied to an address spelled
differently).

**Remaining divergences in the HTTP/3 request path.**

- Protocol upgrades (WebSocket, extended CONNECT) are answered `501` instead of being tunnelled
  (existing `DIV-0004`).

**Tests.** `crates/server/tests/http3.rs`:
`http3_large_upload_streams_through_without_buffering` (600 MiB through to an upstream, byte count
checked, peak memory growth bounded), `http3_early_response_does_not_wait_for_the_upload`,
`http3_streamed_upload_honours_max_request_body_size`,
`http3_buffering_route_keeps_the_buffered_ceiling`,
`http3_stalled_upload_is_cut_off_and_frees_the_connection`,
`http3_content_length_mismatch_is_not_a_success`, `http3_malformed_content_length_is_a_400`,
`http3_early_answer_with_the_upload_still_open_does_not_panic`,
`http3_stalled_request_does_not_block_other_requests_on_the_connection`,
`http3_graceful_shutdown_lets_an_in_flight_upload_finish`,
`http3_forced_shutdown_aborts_an_in_flight_upload`,
`http3_reload_removing_the_listener_does_not_wait_for_in_flight_requests`,
`http3_draining_listener_refuses_new_streams_and_connections`,
`http3_body_reader_survives_repeated_early_cancellation`, `listeners.rs`
(`h3_stream_hazard_tests`),
(`h3_declared_length_tests`), and `crates/server/src/limits.rs`
(`read_idle_timeout_follows_caddys_semantics`).

**Proposed register entry.** *HTTP/3 request bodies stream like HTTP/1.1/2 and stock Caddy, each
request stream is served concurrently, and graceful shutdown drains in-flight requests.* The only
residual HTTP/3 request-path divergences are the `501` for protocol upgrades (`DIV-0004`), the
read-idle timeout being per read rather than a total deadline, and request-body trailers being
discarded.

## 3. `file_server` refuses Windows-only path forms

**Stock Caddy.** `SanitizedPathJoin` (`modules/caddyhttp/caddyhttp.go:252-274`) cleans the URL path
and, if `!filepath.IsLocal(relPath)`, **returns the site root** (the request is mapped to the root,
not refused). On Windows `IsLocal` (Go `internal/filepathlite/path_windows.go:23-54`) is false for a
rooted path, for **any path containing `:`** ("conservative but safe": drive prefixes and NTFS
alternate data streams), for `..` reached through `\`, and for reserved device names
(`isReservedName`: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` including the superscript
digits, `CONIN$`, `CONOUT$`, with an extension rule that defers to `RtlIsDosDeviceName_U`). Stock
`fileHidden` (`modules/caddyhttp/fileserver/staticfiles.go:698-743`) splits the filename on the OS
separator (`\` on Windows) and matches with `filepath.Match`, which is case-sensitive.
Trailing-dot/space names are **not** refused by stock Caddy.

**caddy-rs.** The pre-existing guard split only on `/`, so on Windows `..\`, `C:\`, `\\host` and
`file::$DATA` escaped it. The guard now matches stock Caddy's rejections — rooted paths, any `:`,
`\`-separated `..`, and reserved device names (`is_windows_reserved_name`) — and differs from stock
in three deliberate ways:

1. **Response.** caddy-rs answers `403`; stock maps the request to the site root. (caddy-rs already
   answered `403` for a `/`-separated `..` before this change.)
2. **Trailing dot or space.** Any component ending in `.` or a space is also refused (`403`), because
   Win32 strips those after `hide` and the matchers have run (`secret.env.` opens `secret.env`
   behind `hide *.env`). Stock Caddy does not refuse them.
3. **Device names with an extension** (`NUL.txt`) are refused unconditionally; Go consults
   `RtlIsDosDeviceName_U` because Windows 11 no longer treats `CON.txt` as a device, and the check
   here cannot call it from a portable test.

`hide` on Windows now compares in `/` form (the previous code split on `/` over a `\` path and never
matched a basename, which stock Caddy does match because it splits on the OS separator — so this
removes a divergence) and **case-insensitively**, which is stricter than stock's case-sensitive
`filepath.Match` (stock lets `/.ENV` bypass `hide .env` on a case-insensitive file system).
On other platforms `\` and `:` stay ordinary file-name bytes and behaviour is unchanged.

**Known residual (shared with stock).** 8.3 short names (`/ENV~1`) can still reach a hidden file;
Go's `IsLocal` does not handle them either.

**Tests.** `crates/http/src/file_server.rs`: `windows_separators_and_prefixes_escape_the_root`,
`ordinary_windows_paths_are_served`, `non_windows_treats_backslash_and_colon_as_filename_bytes`,
`handler_refuses_parent_references_and_still_serves_files`. The Windows semantics are tested through
a pure function that takes the platform as a parameter; the workspace does not build natively on
Windows, so there is no Windows end-to-end run.

**Proposed register entry.** *On Windows `file_server` answers `403` (stock: serves the site root)
for rooted paths, `:`, `\`-parent references and device names, and additionally refuses components
ending in a dot or space (stock: served); `hide` matching is case-insensitive on Windows (stock:
case-sensitive).* Class: hardening; Windows only.

## 4. ACME file storage permissions and key validation

**Stock certmagic.** `FileStorage.Store` creates directories `0700` and writes files `0600` through
an atomic file (`filestorage.go:80-98`). It never rewrites the mode of an existing file or
directory (`Load` is a plain `os.ReadFile`, `:105`), and `Filename` is
`filepath.Join(s.Path, filepath.FromSlash(key))` (`:167`) with no key validation. This change
therefore **aligns** new writes with stock and removes a previous divergence (files `0644`,
directories `0755`, applied through the process umask).

**caddy-rs, beyond stock.**

- Material written by older builds is tightened when read (file `0600`) or when a key beneath it is
  rewritten (ancestor directories `0700`). Stock leaves a loose file loose.
- The file-system backend additionally `fsync`s before the rename, uses a unique exclusive temporary
  name, rejects keys containing `\` (and `:` on Windows) and keys that do not name a file (`.`,
  trailing `/`). Stock performs no key validation. Windows has no ACL handling in either.

**Tests.** `crates/tls/src/acme/mod.rs`: `account_key_and_its_directories_are_owner_only`,
`concurrent_stores_of_one_key_never_corrupt_or_leak_temporaries`,
`loose_modes_from_an_older_version_are_tightened`,
`stale_temporaries_do_not_break_or_get_removed_by_later_writes`,
`keys_that_do_not_name_a_file_are_rejected`,
`file_storage_rejects_traversal_and_windows_path_syntax_but_keeps_ports`.

**Not covered here.** The certificate/key store in `crates/tls/src/storage.rs` still writes private
keys at the default mode and tightens them after the rename, and creates `0755` directories; the
internal CA key store has the same directory issue. Both still diverge from stock (`0600`/`0700`
from creation). Tracked as a follow-up.

**Proposed register entry.** None for the permission change on the ACME account path (it removes a
divergence). *Self-healing of loose modes on read/write and storage-key validation are caddy-rs
hardening extensions not present in certmagic.*

## 5. Proxy-manager first-run setup token (caddy-rs extension)

The proxy manager (`pm/`) is a caddy-rs product with no upstream Caddy counterpart, so this is not
a divergence from Caddy. It is recorded for completeness: `POST /api/v1/auth/setup` requires a
one-time `X-Setup-Token` (printed in the daemon log at start-up while no administrator exists) in
addition to the loopback peer and `Host` guards. See `pm/README.md`. The embedded UI bundle in
`pm/ui/dist` must be rebuilt for the UI form to send the token.

**Tests.** `pm/crates/pm-api/src/tests.rs`
(`setup_with_a_token_configured_rejects_a_missing_or_wrong_token`,
`an_empty_setup_token_never_matches_a_missing_header`), `crates/authn/src/tests.rs`
(`setup_tokens_are_long_random_and_distinct`, `secrets_match_requires_exact_equality`),
`pm/crates/pm-cli/src/main.rs` (`setup_requires_a_token_only_while_no_administrator_exists`).
