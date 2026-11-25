# Compatibility note — request-path validation, symlinks and the Windows port

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation changes. This
note records every behaviour in this change that differs from stock Caddy v2.11.9, with the code and
test that pin it, and ends with the proposed register entries. Nothing here claims to know what
upstream does beyond what is stated; where a statement about upstream is from memory rather than
from reading the pinned source it is marked **(unverified)**.

## 1. Symlinks (`file_server`)

**Upstream.** Caddy opens files through the operating system, so every symlink on a requested path is
followed wherever it points. There is no containment option.

**caddy-rs.** `file_server` has a `symlinks` option (a caddy-rs extension, JSON key `symlinks`,
Caddyfile subdirective `file_server { symlinks <policy> }`):

| Policy | Behaviour |
|---|---|
| `within_root` (default) | A symlink (or Windows directory junction) is followed when the file it **resolves to** lies inside the real, canonical root. Anything else is refused with 403. |
| `deny` | Any link below the root is refused with 403 (the previous caddy-rs behaviour). |
| `follow` | Every link is followed wherever it points (stock Caddy behaviour). |

The root itself may be a symlink (the usual `current -> releases/<id>` layout); only components below
it come from the client.

What `within_root` guarantees, and how:

* **Judged by resolution, not spelling.** The path is resolved with `canonicalize` and compared
  component-wise against the canonical root, so `docs/../real.txt`, `../site/real.txt` and
  `../outside/leak.txt` are each judged by where they really land, chains are followed hop by hop, and
  `/srv/site-evil` is not "inside" `/srv/site`.
* **The `hide` list applies to the resolved target.** A link named `innocent.txt` pointing at
  `secret.env` is hidden by `hide *.env`; a link to a hidden directory is hidden. On Windows the
  check also runs against the real long-name path, so an 8.3 alias (`SECRET~1.ENV`) cannot bypass it.
* **Index files and precompressed sidecars follow the same policy.** An `index.html` link, a `.gz`
  sidecar link and an `etag_file_extensions` sidecar link that leave the root are refused (the ETag
  sidecar is ignored rather than leaking a line of the target into the `ETag` header).
* **I/O uses the resolved path and a verified handle.** After a link is crossed, all later lookups use
  the link-free path. The file is opened once and the operating system is asked for the open handle's
  real path (`/proc/self/fd` on Linux, `F_GETPATH` on macOS, `GetFinalPathNameByHandleW` on Windows);
  a handle outside the root is refused, so a path component swapped for a symlink between the check and
  the open cannot redirect the read. The response `Content-Length` is the number of bytes actually read.
* **Failure modes are never 500.** A dangling link is 404; a link loop or any other resolution failure
  is 403.
* **The `Content-Type` follows the requested name**, not the target's (`latest.html -> build-1234.bin`
  is served as HTML), like nginx and Apache.
* **Directory listings** (`browse`) show a link to a directory as a directory, and omit links the policy
  refuses, hidden entries and dangling links, so the listing never advertises something that answers
  403/404.

Residual risk, stated plainly: an attacker who can *write to the served tree* while requests are in
flight can still change what a path names between two requests. The handle check closes the race for
the file that is read; it does not make a writable served tree trustworthy. Platforms that cannot report
a handle's path (other Unixes) rely on the path-based check alone.

Tests: `crates/http/src/file_server.rs` (`symlink_*`, `links_are_judged_by_where_they_resolve*`,
`a_link_to_a_hidden_file_cannot_bypass_hide`, `*_sidecars_*`, `an_etag_sidecar_link_*`,
`browse_lists_followable_links_*`), `crates/http/tests/file_server_path_validation.rs`
(`symlink_policy`, `windows_junction_is_refused`) and `crates/config/tests/file_server_symlinks.rs`.

## 2. Request-path validation (`file_server`)

These refusals are stricter than, or different from, upstream. The vectors come from a survey of other
Rust servers and their path-traversal advisories (see `NOTICE.md`).

| Input | caddy-rs | Note |
|---|---|---|
| Any `..` component (any encoding that decodes to one) | 403 | Upstream cleans the path. Already the behaviour before this change; pinned by the corpus. |
| `%00` (NUL) | 403 | |
| Escapes that do not decode to valid UTF-8 (`%ff`, `%c3%28`, overlong `%c0%ae`) | 404 | Previously decoded lossily to U+FFFD, so different invalid sequences collapsed into one mangled name. Upstream treats the path as bytes **(unverified)**. |
| Double-encoded `%252e%252e` | decoded once; literal name, 404 | Same as upstream. |
| A file used as a directory (`/index.html/x`), an over-long name, an invalid name | 404 | Were reaching the I/O error path as a server error. |

On **Windows only** (the rules take the platform as a parameter and are unit-tested on every OS):

| Input | caddy-rs | Why |
|---|---|---|
| `\` parent references (`..\x`), `C:` drive prefixes, rooted or UNC (`\x`, `\\host\share`) | 403 | `PathBuf::join` would discard the root. RUSTSEC-2022-0069/-0043/-0082 class. |
| `:` anywhere (alternate data streams `f::$DATA`, `f.txt:stream`) | 403 | |
| A component ending in `.` or space (`secret.env.`) | 403 | Win32 strips them after `hide` ran, so `secret.env.` opened `secret.env`. |
| Reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1-9`, `LPT1-9` (`COM0`/`LPT0` are ordinary names, as in Go), superscript digits, with or without an extension, any case) | 403 | Opening them reaches a device; stock Caddy refuses them as non-local paths (`filepath.IsLocal`). |
| Characters Windows cannot store (`< > " | ? *`, control characters) | 404 | Would otherwise surface as an invalid-name error. |

Names that merely resemble these (`COM10.txt`, `NULL.txt`, `CONIN.txt`, `contact.html`) are served.

Windows `hide` handling also changed: entries and request paths are compared in `/` form (a path spelled
`C:\site\caddy` previously contained no `/`, so it was treated as a basename glob and matched nothing,
including the automatic hide of the config directory, which holds `autosave.json`) and
case-insensitively; macOS compares case-insensitively too (`/.ENV` must not slip past `hide .env`).
`browse` listings no longer show entries the `hide` list covers.

Tests: `crates/http/tests/file_server_path_validation.rs` (the corpus, run as GET and HEAD) and the
`request_path_*` / `windows_*` tests in `crates/http/src/file_server.rs`.

## 3. `file` matcher and `try_files` on Windows

* The matcher builds `/`-separated candidate paths and Go-style globs. A Windows root `C:\site` is now
  normalised to `C:/site`; before, **nothing under a Windows root ever matched**.
* `{http.matchers.file.absolute}` is spelled with `\` on Windows (Go's `filepath.Join`); `relative`
  stays `/`-separated.
* Placeholder values are glob-escaped. On Unix that is `\*` as before. On Windows `\` is the separator
  and is normalised to `/`, which destroyed the escape, so a request for `/assets/*` became a live
  glob. Upstream does not escape on Windows **(unverified)**; caddy-rs escapes with one-character classes
  (`[*]`, `[?]`, `[[]`), which survive normalisation.
* On Windows the matcher refuses the same alias forms as `file_server` (`a.txt:stream`, `index.html.`),
  so `try_files` cannot select a file that `file_server` would then reject.
* Template `include`/`readFile` names on Windows refuse `:`, trailing dot/space and device names; `..`
  is still clamped to the root as before.

## 4. The Windows port (platform differences, not behaviour changes)

| Area | On Windows |
|---|---|
| `unix//path` listeners and Unix-domain admin sockets | Refused at load with a located error pointing at TCP (tokio has no Unix listener there). |
| systemd socket activation (`LISTEN_FDS`) | Ignored (`from_env` returns none); inherited-descriptor APIs return a located error. |
| systemd fd store (`bind-fds`) | Stub that reports "no systemd fd store on this platform". |
| Graceful restart (`ecdysis`, default-off feature) | Unavailable; Windows builds use `--exclude ecdysis`. |
| Binding ports below 1024 | No capability escalation (none needed). |
| Shutdown signals | Ctrl+C, Ctrl+Break, console close and system shutdown map to the SIGINT/SIGTERM counter; a second one forces shutdown. |
| Private files and directories | Created with a protected owner/SYSTEM/Administrators DACL (the Windows analogue of `0600`/`0700`); `chmod` does nothing there. |
| Data directory, autosave and Caddyfile `import` safety rules | Enforced from the file's DACL and owner instead of mode bits and uid. |
| JWT signing key (proxy manager) | Refused when another principal can read or write it, created private. |
| Entry-point stack | The program runs on a 16 MiB thread (Tokio workers 8 MiB); Windows gives the main thread 1 MiB. |
| Upstream TLS and ACME trust roots | No PEM bundle exists on Windows; the operating-system certificate store is used when `SSL_CERT_FILE`/the Linux bundle paths yield nothing (`rustls-native-certs`). |
| ACME CA directory with a port (`https://localhost:14000/dir`) | The on-disk issuer directory drops the `:` on Windows (`localhost14000-dir`), as CertMagic's key sanitiser does everywhere; a `:` is not a valid directory name there. Linux keeps `localhost:14000-dir` (existing data stays valid). |
| `respond` with a body on stdin | Only a real pipe (`GetFileType == FILE_TYPE_PIPE`) supplies the body, matching Caddy's named-pipe test; a redirected file or `NUL` does not. |
| Oversized body answered early (413/503) | The server answers and closes while the client is still sending. Linux normally delivers the response; on Windows unread data makes the TCP stack reset the connection, so the client may see a reset instead of the status code. A lingering close on the server would remove the difference (follow-up). |

## Proposed divergence register entries

1. **file_server symlink containment (default `within_root`)** — caddy-rs follows symlinks whose real
   target is inside the root and refuses others; stock Caddy follows all. Opt back in with
   `symlinks follow`. Also hides resolved targets, applies the policy to index files and sidecars, and
   verifies the opened handle.
2. **Strict UTF-8 in file request paths** — invalid escapes are 404 instead of a lossy lookup.
3. **Windows request-path refusals** — `:`/trailing-dot/space 403; reserved device names and unstorable
   characters 404.
4. **Windows glob escaping with character classes** — placeholder values cannot become globs.
5. **`browse` omits hidden, refused and dangling entries.**
6. **Windows platform differences** listed in section 4.
