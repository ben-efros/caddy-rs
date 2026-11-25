# SEC-MEDIUM-HTTP compatibility note — HTTP handler hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records the medium/low-severity security findings fixed in `crates/http` and states, per
finding, whether the fix changes behaviour relative to stock Caddy v2.11.9. Every finding below is
either behaviour-preserving (applied unconditionally, no `stock_compat` flag) or documented as a
deliberate non-change. No finding in this group introduces a divergence, so there is no proposed
register entry; the "Register" line of each section says so explicitly.

## B1. `basic_auth`: password hashing offloaded from the async workers

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/caddyauth/basicauth.go` `HTTPBasicAuth.Authenticate` verifies the password
  inline in the request goroutine; Go goroutines are cheap, so a slow bcrypt/Argon2 comparison
  stalls only that request. It also offers an optional `hash_cache` (`HashCache`) memoising
  comparisons. For unknown users Caddy verifies against the fixed fake hash
  (`BcryptHash.FakeHash` / `Argon2idHash.FakeHash`) so account existence is not a timing oracle.
- This port does **not** implement `hash_cache` (the field is not accepted by `from_json`'s
  provider schema), so nothing was removed. It is unrelated to this fix.

### Vulnerability and fix

The previous implementation called `bcrypt::verify` / `Argon2::hash_password_into` directly inside
the async `handle`. The unknown-user fake hash is bcrypt cost 14 (about a second of CPU). A tokio
worker that runs it cannot service any other task, so a handful of concurrent requests carrying bad
Basic credentials occupied every worker thread and the whole server (all vhosts, all handlers)
stopped answering until they finished.

`verify_password_offloaded` now runs bcrypt and Argon2id on the blocking pool via
`tokio::task::spawn_blocking`, behind a process-wide `tokio::sync::Semaphore` sized to
`max(2, available_parallelism)`. Requests beyond the limit wait asynchronously for a permit (they
hold no worker thread); they are **never rejected**, so the 401 challenge / continue behaviour and
status codes are exactly Caddy's. The limiter also bounds peak Argon2 memory (`m=47104` KiB per
concurrent verification). The unknown-user path goes through the identical offload with the same
fake hash for the configured algorithm, so the timing-equalisation property is unchanged. The
`plaintext` extension is a constant-time compare of a short value and stays inline.

### stock_compat

Behaviour-preserving, so unconditional: identical in both `stock_compat` settings. No 429/503 is
introduced (waiting was chosen over rejecting precisely to avoid a divergence).

### Tests

`crates/http/src/auth.rs`: `bad_credentials_do_not_starve_the_async_workers` (one-worker runtime,
eight in-flight unknown-user requests, an unrelated task must complete within 1.5 s; took ~22 s
before the fix), `hash_verification_limiter_caps_concurrency_without_rejecting`,
`hash_verification_limit_is_a_small_multiple_of_parallelism`,
`offloaded_verification_still_accepts_and_rejects_each_algorithm`, plus the pre-existing bcrypt /
Argon2id vector and timing-equalisation tests, which run unchanged through the new path.

Register: no divergence; no entry proposed.

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

Now the order is: `stat` only, then preconditions (304/412), then HEAD (never opens the file), then
the range plan (`apply_ranges` describes the body as `BodySegment`s: literal multipart framing plus
`File { start, length }` spans; nothing is read to plan), then only those spans are read. A GET
opens the file after the preconditions and checks ranges against the length of the open handle (the
"file changed while it was being served" 416 behaviour is preserved). A body whose file content is
at most 256 KiB is read inline exactly as before. A larger body is handed to the streaming path:
`FileServerHandler::handle_streaming` (the entry point the server uses through
`Router::handle_upgradable`) returns the open file as a chunked `StreamingBody` (64 KiB chunks over
a small bounded channel, so a slow client applies backpressure and memory stays flat). The buffered
`Handler::handle` API (used by direct callers and tests) still materialises the body, but now only
the requested spans. Headers, `ETag`, precompressed sidecars, `Content-Length`, multipart framing
and `Accept-Ranges` are produced by the unchanged shared code.

Residual differences, none reachable with a stable file: if a file shrinks after the headers are
sent the streamed body ends with an I/O error (connection aborted, like Go's short `io.CopyN`) and
on the buffered path a read shorter than planned is a 500 instead of a silently short body.

### stock_compat

Behaviour-preserving for every valid request: identical in both `stock_compat` settings.

### Tests

`crates/http/src/file_server.rs`: `range_head_and_not_modified_of_a_huge_file_do_not_load_it`
(1 GiB sparse file; peak RSS growth measured via `/proc/self/status` `VmHWM`, reset with
`/proc/self/clear_refs`; before the fix growth was ~1 GiB for range, HEAD and 304),
`large_full_get_is_streamed_not_buffered` (512 MiB sparse file consumed frame by frame; before the
fix ~460 MB at the earlier 256 MiB size), `streamed_bodies_match_the_content_and_buffered_framing`,
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
`file_root` narrow (file functions are already confined to it).

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
