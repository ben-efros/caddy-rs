# SEC-MEDIUM-HTTP compatibility note — HTTP handler hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records the medium/low-severity security findings fixed in `crates/http` and states, per
finding, whether the fix changes behaviour relative to stock Caddy v2.11.9. Findings are either
behaviour-preserving (applied unconditionally), documented as a deliberate non-change, or an
explicit divergence/extension with a proposed register entry: B1 (capped wait for a hash permit,
`stock_compat` aware), B3 (path-style `hide` entries also hide listing entries) and B5 (opt-in
`env_allow`). The "Register" line of each section says which applies.

## B1. `basic_auth`: password hashing offloaded, bounded and cached

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/caddyauth/basicauth.go` `HTTPBasicAuth.Authenticate` verifies the password
  inline in the request goroutine; Go goroutines are cheap, so a slow bcrypt/Argon2 comparison
  stalls only that request, and there is no limit on concurrent comparisons. It also offers an
  optional `hash_cache` (`HashCache`) memoising comparisons (success and failure, capped at 1000
  entries). For unknown users Caddy verifies against the fixed fake hash
  (`BcryptHash.FakeHash` / `Argon2idHash.FakeHash`) so account existence is not a timing oracle.

### Vulnerability and fix

The previous implementation called `bcrypt::verify` / `Argon2::hash_password_into` directly inside
the async `handle`. The unknown-user fake hash is bcrypt cost 14 (about a second of CPU). A tokio
worker that runs it cannot service any other task, so a handful of concurrent requests carrying bad
Basic credentials occupied every worker thread and the whole server (all vhosts, all handlers)
stopped answering until they finished.

1. **Offload.** `BasicAuthHandler::verify_offloaded` runs bcrypt and Argon2id on the blocking pool
   (`spawn_blocking`) behind a process-wide `tokio::sync::Semaphore` sized to
   `max(2, available_parallelism)`, which also bounds peak Argon2 memory (`m=47104` KiB per
   concurrent verification). The unknown-user path takes the identical route with the same fake
   hash, so timing equalisation is unchanged. The `plaintext` extension is a constant-time
   compare of a short value and stays inline.
2. **Permit lifetime.** The permit is an `OwnedSemaphorePermit` moved INTO the blocking closure.
   If the request future is dropped (HTTP/2 `RST_STREAM`, timeout) the detached hash keeps its
   permit until it really finishes, so cancelled requests cannot multiply concurrent hashes past
   the limit (an earlier revision released the permit with the future and allowed that).
3. **`hash_cache`.** Repeated (stored hash, password) pairs are answered from a bounded
   (1000 entries, arbitrary-entry eviction) cache of results, success and failure, like Caddy's
   `HashCache`, so legitimate clients (browsers resend credentials on every request) neither pay
   the hash again nor queue behind an attacker. The key is
   `HMAC-SHA256(per-handler random secret, len(hash) || hash || password)`, so the map cannot be
   used as an offline password-guessing oracle. It is built-in and always on (Caddy's is an
   opt-in field; this port does not accept a `hash_cache` JSON field) and is unconditional.
   Results are cached from inside the blocking job, so a hash whose request was cancelled still
   pays off. Not copied from Caddy: its in-flight de-duplication of identical concurrent
   comparisons; identical concurrent uncached pairs each compute once.
4. **Bounded wait.** Without a limit on waiting, an attacker sending more than the pool's
   throughput grows an unbounded queue and every uncached login waits behind it. Under the secure
   default a request that waits more than 5 seconds for a hash permit gets
   `503 Service Unavailable` with `Retry-After: 5` (no challenge, no hash). `stock_compat: true`
   waits indefinitely, as stock Caddy effectively does. Cached credentials are never affected.
   The cap is a wait time, not a queue depth: queue length is bounded by request rate times 5 s.

### stock_compat

Items 1 to 3 are behaviour-preserving (identical status codes and results) and apply in both
settings. Item 4 is a divergence under the secure default: the 503 + `Retry-After` is
`stock_compat`-gated (`BasicAuthHandler::from_json_with_stock_compat`, fed from
`HandlerBuildContext::stock_compat`); `stock_compat: true` keeps unbounded waiting.

### Tests

`crates/http/src/auth.rs`:
- `bad_credentials_do_not_starve_the_async_workers` (one-worker runtime, eight in-flight
  unknown-user requests, an unrelated task must complete within 1.5 s; ~22 s before the fix);
- `cancelled_requests_keep_their_permit_until_the_hash_finishes` (fails before the permit fix:
  peak in-flight hashes 4 with a limit of 2 after two requests were cancelled; instrumented
  counter);
- `hash_cache_answers_repeat_credentials_while_the_pool_is_exhausted` (cache hit/miss for success
  and failure, proven by exhausting the pool), `queue_wait_is_capped_with_503_and_retry_after_by_default`,
  `stock_compat_waits_for_a_permit_without_a_cap`,
  `hash_cache_keys_are_secret_keyed_and_the_cache_is_bounded`;
- `hash_verification_limiter_caps_concurrency_without_rejecting`,
  `hash_verification_limit_is_a_small_multiple_of_parallelism`,
  `offloaded_verification_still_accepts_and_rejects_each_algorithm`, plus the pre-existing bcrypt /
  Argon2id vector and timing-equalisation tests, which run unchanged through the new path.

Register: divergence for item 4 only. Proposed entry:

```
- DIV id: (assign)
- Area: HTTP
- Caddy behaviour: `basic_auth` verification has no concurrency limit and no wait limit.
- caddy-rs behaviour: hash computations run on a bounded pool (max(2, cores)); under the secure
  default a request waiting more than 5 s for a slot gets 503 + `Retry-After: 5`;
  `stock_compat: true` waits without limit.
- Rationale: stops a bad-credential flood from growing an unbounded queue that delays every login.
- Status: intentional hardening (stock_compat restores stock behaviour)
- Test: `crates/http/src/auth.rs` `queue_wait_is_capped_with_503_and_retry_after_by_default`,
  `stock_compat_waits_for_a_permit_without_a_cap`
```

## B2. `file_server`: the file is no longer read into memory per request

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/fileserver/staticfiles.go` opens the file and hands the `*os.File` to
  `http.ServeContent` (`net/http/fs.go`), which evaluates preconditions from the validators
  (`checkPreconditions`), answers HEAD without reading, `Seek`s to a range start and copies only
  `io.CopyN(w, sendContent, sendSize)` bytes. Caddy never holds a whole file in memory; the default
  `Etag` is mtime plus size (`calculateEtag`), not a content hash.

### Vulnerability and fix

`serve_file` called `fs::read(&representation)` before preconditions, Range and HEAD handling. A
request for one byte of a multi-GiB file, a HEAD, or a request that ends in a 304 still allocated
and filled the whole file; a few concurrent requests for a large artifact exhausted memory.

Now `serve_file` opens the representation exactly once (as Caddy does, so HEAD of an unreadable
file fails like GET instead of answering 200 headers) and takes every validator (ETag,
Last-Modified source, size, is-regular-file) from that handle's `fstat`. The order is then:
preconditions (304/412), the range plan (`apply_ranges` describes the body as `BodySegment`s:
literal multipart framing plus `File { start, length }` spans; nothing is read to plan), and only
then the spans a GET actually carries are read from the same handle; a HEAD drops the handle
without reading. A body whose file content is at most 256 KiB is read inline exactly as before.
A larger body is handed to the streaming path: `FileServerHandler::handle_streaming` (the entry
point the server uses through `Router::handle_upgradable`) returns the open file as a chunked
`StreamingBody` (64 KiB chunks over a small bounded channel, so a slow client applies backpressure
and memory stays flat). The stream reports an exact size (`StreamingBody::from_chunks_with_len`),
so `to_hyper_streaming` keeps `Content-Length` for the 200, single-range 206 and multipart 206
responses exactly as Go's `ServeContent` sets it (an earlier revision lost it and fell back to
chunked framing). The buffered `Handler::handle` API (direct callers and tests) still materialises
the body, but now only the requested spans.

Open-once also closes a stat-then-reopen race that predates B2: the symlink policy is "refuse"
(`path_contains_symlink` on the path), but the file used to be reopened afterwards following
symlinks and served under the validators of the earlier path `stat`. On unix the open now uses
`O_NOFOLLOW | O_NONBLOCK` (constants from the `libc` crate, no unsafe; a final symlink swapped in
after the check fails with `ELOOP` and is answered 403; a FIFO swapped in cannot hang the open and
is rejected as not-a-file). Residual: `O_NOFOLLOW` covers only the last component, so an
intermediate directory swapped for a symlink inside that window is still followed; closing that
needs `openat2(RESOLVE_NO_SYMLINKS)` or a per-component `openat` walk. Non-unix targets rely on
the path check only.

Residual differences, none reachable with a stable file: if a file shrinks after the headers are
sent the streamed body ends with an I/O error (connection aborted, like Go's short `io.CopyN`) and
on the buffered path a read shorter than planned is a 500 instead of a silently short body.

### stock_compat

Behaviour-preserving for every valid request: identical in both `stock_compat` settings.

### Tests

`crates/http/tests/file_server_memory.rs` (own test binary so no unrelated test shares the process
counters, serialised by a mutex, Linux only, skipped with a printed note when
`/proc/self/clear_refs` is not writable):
`range_head_and_not_modified_of_a_huge_file_do_not_load_it` (1 GiB sparse file; peak RSS growth
via `VmHWM`; against the pre-B2 `file_server.rs` growth was ~1 GiB for range, HEAD and 304),
`large_full_get_is_streamed_not_buffered` (512 MiB sparse file consumed frame by frame; ~514 MiB
growth against the pre-B2 code) and `rss_meter_detects_a_buffered_read` (calibration: the meter
must see a deliberate 300 MiB allocation, otherwise the other two would pass vacuously).

`crates/server/src/http.rs`: `streamed_static_files_keep_content_length_through_to_hyper_streaming`
(200, single-range 206 and multipart 206 over 256 KiB through `to_hyper_streaming`; failed before
with "Content-Length was dropped").

`crates/http/src/file_server.rs` (a test seam runs between the path checks and the open so the
swap is deterministic): `symlink_swapped_in_after_the_path_check_is_refused` (served the first
bytes of the outside file before the fix, now 403),
`validators_come_from_the_opened_file_not_a_stale_stat` (ETag/Content-Length/body of a file swapped
in after the stat; failed before), `head_of_an_unreadable_file_fails_like_get` (skipped when running
as a user that bypasses file permissions; failed before), plus
`streamed_bodies_match_the_content_and_buffered_framing`,
`small_bodies_are_not_streamed`, `range_variants_read_exactly_the_requested_bytes` (start, middle,
end, suffix, open-ended, multiple ranges, `If-Range` match and mismatch, 416, HEAD+Range),
`read_segments_reports_a_file_shorter_than_planned`, and the pre-existing `apply_ranges` /
multipart unit tests adapted to the span-based plan. `crates/http/tests/file_server_streaming.rs`
checks the router (including a nested `subroute`) delivers large bodies as streams.

Register: no divergence; no entry proposed.

## B3. `file_server` browse: the listing honours `hide`

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/fileserver/browse.go` builds the listing in `directoryListing`, which skips
  every entry for which `fileHidden(name, filesToHide)` is true (`filesToHide` comes from
  `transformHidePaths`). The same `fileHidden` decides the 404 in `staticfiles.go`. This note is
  written from knowledge of upstream, not from an oracle run.

### Vulnerability and fix

`browse_html` never consulted the `hide` list, so a directory listing named (and, with
`plain_time_format`, dated) `.env`, `.git` and every other hidden entry even though fetching them
answered 404. `browse_html` now skips an entry when the handler's own `hidden()` predicate (the one
used for the fetch decision, including placeholder expansion and glob/path semantics) matches the
entry's filesystem path. The listing is HTML only in this build; there is no JSON listing to fix.

One nuance: the predicate runs on the entry's full path (the same form the fetch check uses), so a
path-style `hide` entry (an absolute path) also hides the matching entry from the listing. Upstream
passes the bare entry name to `fileHidden`, so there such an entry is still listed even though it
cannot be fetched. This port keeps listing and fetch consistent; for the common name/glob entries
(`.env`, `.git`, `*.bak`) behaviour equals upstream.

Name-only patterns match any component of the entry's path, as in the fetch check. That is
equivalent to matching the bare entry name: if a component of the listed directory itself matched
(for example `hide [".*"]` with root `/home/u/.www`), the request for that directory is already
answered 404 by the fetch-side `fileHidden` check before any listing is built, so a matching
ancestor can never silently empty a listing. (`browse_hide_matches_entry_names_and_an_ancestor_match_404s_the_request`
pins this; it is a characterisation test and passes on the earlier revision too.) The `hide`
entries (placeholders, absolute paths, working directory) are now expanded once per listing rather
than once per entry and pattern.

### stock_compat

Identical in both settings: the file server is not given the flag, and the difference above only
concerns path-style `hide` entries, where hiding more than upstream is the secure direction.

### Tests

`crates/http/src/file_server.rs`: `browse_listing_omits_hidden_entries_in_the_root_and_in_subdirectories`
(failed before: the root listing contained `.env`, `.git`, `notes.bak` and their times),
`browse_listing_is_unchanged_without_hide_and_honours_path_entries` (no `hide` lists everything;
absolute-path entry hides only that entry).

Register: no divergence for name/glob entries. Proposed entry for the path-style nuance:

```
- DIV id: (assign)
- Area: HTTP
- Caddy behaviour: `browse` filters directory entries with `fileHidden(<bare entry name>)`, so a
  path-style `hide` entry (absolute path) never matches in the listing although it makes the file
  unfetchable.
- caddy-rs behaviour: the listing applies the same predicate as the fetch path to the entry's full
  path, so path-style `hide` entries also hide the entry from the listing.
- Rationale: listing and fetch must not disagree about what is hidden; the listing leaked names and
  modification times of files the operator marked hidden.
- Status: intentional hardening
- Test: `crates/http/src/file_server.rs`
  `browse_listing_is_unchanged_without_hide_and_honours_path_entries`
```

## B4. Dotfiles are served by default (documented, unchanged)

Stock Caddy serves dotfiles (`.env`, `.git/...`) unless `hide` excludes them, and so does this
build: matching stock behaviour is intentional and nothing was changed. Operators exposing a
directory that may contain such files must configure `hide` explicitly, for example
`"hide": [".*"]` (any path component starting with a dot) or specific names such as `".env"` and
`".git"`; with B3 the setting now applies to the browse listing as well as to fetches. Caddy always
auto-hides its own config and data directories (see `auto_hide_entries`); that is unrelated.

Register: no divergence; no entry proposed.

## B5. `templates`: `env` function and default root (stock parity kept, opt-in allow list added)

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/templates/tplcontext.go` `funcEnv` returns `os.Getenv(varName)` for any name,
  and the `placeholder` function resolves `env.NAME` through the replacer, so a template author can
  read every process environment variable (database passwords, API keys). The default `file_root`
  is the request's `{http.vars.root}`, falling back to the working directory (`templates.go`
  `Provision`/`ServeHTTP`). This build matches both, intentionally; neither was changed.

### Opt-in hardening: `env_allow`

A caddy-rs extension field on the `templates` handler, `env_allow`: an array of exact environment
variable names (non-empty strings; matching is case-sensitive). When present, `env "NAME"` and
`placeholder "env.NAME"` / `ph "env.NAME"` (which would otherwise bypass the list) can read only
the listed variables; any other name aborts the template with an execution error, which the
transform reports as an empty 500 (a loud failure, not an empty string that would hide the
misconfiguration). `env_allow: []` denies every variable. Absent or `null` is exactly stock
behaviour. A non-array value or a non-string/empty element is a located config error
(`<path>.env_allow` / `<path>.env_allow[N]`).

Recommended for any deployment where template authors are less trusted than the process owner.
Related operator guidance: do not run `templates` over content users can upload, and keep
`file_root` narrow (file functions are already confined to it). `env_allow` only governs the
`env` function and `env.` placeholder: if `file_root` covers `/` (or `/proc`), a template can still
`readFile "/proc/self/environ"` and read the whole environment, so a narrow `file_root` is part of
the same control, not optional.

### stock_compat

Not tied to `stock_compat`: the field is opt-in, so omitting it is stock Caddy in both modes, and
setting it is an explicit operator choice that `stock_compat` does not override.

### Tests

`crates/http/src/templates.rs`: `env_is_unrestricted_without_env_allow_like_stock_caddy`,
`env_allow_restricts_env_and_the_env_placeholder`, `empty_env_allow_denies_every_variable`,
`env_allow_config_is_validated_with_located_errors` (the last three failed before: `env_allow` was
an unknown field).

Register: extension, no divergence from stock for existing configurations. Proposed entry:

```
- DIV id: (assign)
- Area: HTTP
- Caddy behaviour: the `templates` `env` function and the `env.` placeholder read any process
  environment variable; there is no way to restrict them.
- caddy-rs behaviour: the optional `env_allow` field (array of exact names) restricts both to the
  listed variables; other names are a template error (HTTP 500). Absent = stock behaviour.
- Rationale: opt-in defence in depth against secret disclosure by template authors without changing
  any existing configuration.
- Status: extension
- Test: `crates/http/src/templates.rs` `env_allow_restricts_env_and_the_env_placeholder`
```
