# T-CLI-008 compatibility note — `caddy-rs respond`

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task adds the `respond` subcommand. The note below states only behaviour this implementation can
point at a test or an oracle measurement for; the proposed register entry is at the end.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- `modules/caddyhttp/staticresp.go` — `respond` command registration (`init`): the usage string,
  `-l/--listen` (default `:0`), `-s/--status` (default 200), `-b/--body`, `--access-log`,
  `-v/--debug`, `-H/--header` (`StringArray`), and the long help text.
- `modules/caddyhttp/staticresp.go::cmdRespond` — argument/flag precedence, stdin body
  (`os.ModeNamedPipe`), header parsing (`Field: value` via `strings.Cut` + `TrimSpace` +
  `http.Header.Set`), `ParseNetworkAddress` and port-range expansion, per-server
  `buildHTTPServer`, admin disabled + `config.persist=false`, and the `Server address:` output.
- `modules/caddyhttp/staticresp.go::buildHTTPServer` — the body template context
  (`{{.N}}`/`{{.Port}}`/`{{.Address}}`), the `static_response` handler, `ReadHeaderTimeout: 10s`,
  `IdleTimeout: 30s`, `MaxHeaderBytes: 10 KiB`, `AutoHTTPS.DisableRedir`, and `logs` for
  `--access-log`.
- `modules/caddyhttp/staticresp.go::StaticResponse.ServeHTTP` — status default 200, configured
  header application, implicit `Content-Type` (`application/json` for a valid JSON object/array,
  otherwise `text/plain; charset=utf-8`) only when the body is non-empty and no `Content-Type` is
  set, and body suppression for 1xx/204/304 by the Go HTTP server.
- `listeners.go::ParseNetworkAddress`/`SplitNetworkAddress` — network prefix, omitted port,
  inclusive port ranges; `JoinHostPort` drops the network prefix when `cmdRespond` rebuilds a
  non-Unix listen address.

## Implemented behaviour

`crates/cli/src/respond.rs` builds an in-memory `caddy_rs_core::Config` with `admin.disabled =
true`, `admin.config.persist = false`, one `static_response` route per server, and runs it through
the same `GenerationStore`/`ServerRuntime` as `caddy-rs run` (with socket activation disabled). It
prints the actual bound address(es) as `Server address: <addr>` and blocks until
`SIGINT`/`SIGTERM`.

| Input | Result |
|---|---|
| `respond` | `:0` (dual-stack, random port), empty 200, prints the bound address |
| `respond 404` | 404, empty body |
| `respond hello` | 200, body `hello`, `text/plain; charset=utf-8` |
| `respond --status 200 404` | 200, body `404` |
| `respond --body '{"a":1}'` | `application/json` |
| `respond --header "X-Test: yes"` | response header `X-Test: yes`; repeated fields replace |
| `respond --header "Bad Header: x"` | starts; the invalid field is dropped (matches Go's writer) |
| `respond --header $'X-Test: a\nb'` | starts; value served as `a b` (Go replaces CR/LF) |
| `respond -l 127.0.0.1:8000-8001` | one server per port, each printed |
| `respond -l unix//tmp/x.sock` | plain HTTP over the Unix stream socket |
| `respond -l tcp4/127.0.0.1:8080` | plain TCP; Caddy drops the prefix, so caddy-rs does too |
| `respond -l udp4/127.0.0.1:8080` | plain TCP (Caddy's `JoinHostPort` drops `udp4/` too) |
| `respond < file` | stdin is **not** read (regular file, matching `os.ModeNamedPipe`) |
| `echo x \| respond` | body from stdin |
| `respond --access-log` | access entries on stderr (this build's access-log JSON) |
| `respond` with `LISTEN_FDS=1`/`LISTEN_PID=$$` | starts normally; `respond` ignores socket activation |
| `respond --debug` | exit 1, located error naming `--debug` |
| `--status 99` / `--status 1000` | exit 1, located error naming `--status` and `200-999` |
| `--status 100/102/103/199` | exit 1, located error naming `--status` and the interim 1xx status |
| `--listen udp/:0` / `fd/3` / `unixpacket//tmp/x.sock` | exit 1, located error naming `--listen` |
| two unnamed arguments | exit 1, `too many unflagged arguments` |
| `--status`+`--body`+unnamed argument | exit 1, `unflagged argument "<arg>" is overridden by flags` |
| `--header` without `Field: value` | exit 1, Caddy's `header <i>: invalid format ...` |
| a template other than `{{.N}}`/`{{.Port}}`/`{{.Address}}` | exit 1, located error naming the body source |

Argument precedence reproduces Caddy exactly, including its `os.Args` check: an unnamed 3-digit
numeric argument is the status only when the literal string `--status` is absent from `argv`, so
`--status=404 200` behaves like Caddy (the argument wins) and `-s 201 404` behaves like Caddy (the
argument wins). Numeric arguments outside 100-999 are ignored rather than used as a body, also
matching `cmdRespond`'s `Atoi` branch.

## Server limits

Caddy's `buildHTTPServer` limits are mirrored in the in-memory server object
(`idle_timeout: "30s"`, `read_header_timeout: "10s"`, `max_header_bytes: 10240`), and the unit test
`config_matches_caddy_respond_shape` pins all three.

- **Read-header timeout (10 s): enforced.** A header sent 11 s after the request line is not
  answered; the connection is closed. `respond_applies_caddys_read_header_timeout` covers this.
- **Idle timeout (30 s): applied.** Measured against the oracle: after a keep-alive request, both
  binaries had closed the connection before a 35 s follow-up.
- **Maximum header bytes: set, but not equivalent to Go's `MaxHeaderBytes`.** The runtime uses the
  field as hyper's HTTP/1 read-buffer cap, not as Go's post-parse header-size limit. Measured on
  raw HTTP/1.1 (single write, `X-Pad`): 12,000 bytes -> 200 in both; **16,000 bytes -> Caddy 431,
  caddy-rs 200**; 20,000 bytes -> 431 in both. This residual is registered in DIV-0118; the note
  does not claim 10 KiB header parity.

## Divergences from Caddy v2.11.9

| Area | Caddy v2.11.9 | caddy-rs | Why |
|---|---|---|---|
| `--debug` | accepted; raises the default log level to DEBUG and emits internal debug logs | exit 1 with `--debug is not supported by this build ...` | This build has no debug-level internal logging. Silently accepting the flag would claim a capability it does not have. |
| 1xx statuses | sends the interim response (`100 Continue`, `102 Processing`, `103 Early Hints`, `199 status code 199`) and then a final 200 (with the body, except 103) | exit 1 at startup naming `--status` and the interim status | This build has no interim-response plumbing; answering every request with a 500 would be a silent approximation. |
| `--status` outside 100-999 | accepted; the server starts and Go panics per request (`invalid WriteHeader code`) | exit 1 at startup naming `--status` | A per-request panic is not a useful behaviour to reproduce; fail-closed at startup is safer and still loud. |
| `--listen unix/relative.sock` | creates a socket relative to the process working directory and starts | exit 1 naming `--listen` | A socket whose location depends on the caller's working directory is a footgun; refusing it is explicit. |
| `--listen unixpacket/...` | SOCK_SEQPACKET Unix socket (a STREAM client gets `EPROTOTYPE`); starts | exit 1 naming `--listen` | caddy-rs serves HTTP/1.1 over stream sockets only; mapping seqpacket to stream would be a silent approximation. |
| `--listen unixgram/...` | exits 1 (`network 'unixgram' cannot handle HTTP/1 or HTTP/2 connections`) | exit 1 naming `--listen` | Same class as `unixpacket`; caddy-rs fails earlier and with a located message. |
| `--listen fd/...` | adopts the inherited descriptor | exit 1 naming `--listen` | Not implemented for this command; `respond` also deliberately ignores `LISTEN_FDS`. |
| Unix socket permissions (`unix//path\|0666`) | applied | exit 1 naming `--listen` | Not implemented by the listener. |
| body template | full Go `text/template` | only `{{.N}}`, `{{.Port}}`, `{{.Address}}`; anything else is a located error | A Go template engine is not available; rejecting unsupported expressions keeps the limitation loud. |
| header value bytes other than CR/LF | CR/LF become spaces; other control bytes are written through | CR/LF and other control bytes the Rust header type cannot carry become spaces | The transport cannot emit other control bytes; the response is 200 instead of a per-request 500, and the value stays visible. |
| maximum header bytes | 10 KiB `MaxHeaderBytes` (Go adds slack; 16,000-byte header -> 431) | field set to 10240, but used as hyper's read-buffer cap (16,000-byte header -> 200) | Runtime limitation; measured and registered rather than claimed as parity. |
| port-range output order | Go map iteration, unspecified | configured port order | Deterministic output is a superset of Caddy's contract; the addresses themselves are identical. |
| `--header` field names | canonical `X-Test` | lower-case `x-test` | The Rust HTTP stack lower-cases field names; HTTP/1.1 field names are case-insensitive (server-level, already registered). |
| `Server: Caddy` | set on every response | not set | Already registered for the server runtime (DIV-0016 residual). |
| 304 with a body | Go strips `Content-Type` | `Content-Type` is kept | Server-level (hyper does not apply Go's 304 header stripping); the status line and empty body match. |
| status 600 reason phrase | `600 status code 600` | `600 <none>` | Server-level status-line rendering for non-standard codes. |
| access-log format | Caddy's `http.log.access` JSON with `Server: Caddy` in `resp_headers` | this build's access-log JSON | Already registered access-log divergence; `--access-log` reuses it rather than inventing a second sink. |
| error envelope | zap JSON log line | `caddy-rs: error: <message>` | CLI-wide DIV-0023. |
| help text | long help on `-h` and `--help`, usage ending in `[flags]` | clap's short help on `-h`, long help on `--help`, no `[flags]` suffix | CLI-wide DIV-0023; not claimed as exact help parity. |

## Oracle evidence

Pinned oracle: `/root/caddy-rs/.scratch/oracle-eval-2.11.9/caddy` (`v2.11.9`).

Build:

```sh
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target \
cargo build --offline --locked -p caddy-rs
```

Differential probe: `/root/caddy-rs/.scratch/logs/t-cli-008-diff/diff.py` starts each binary on a
fresh loopback port, issues a real HTTP/1.1 request, and compares the status line, headers
(normalized; `Date` and `Server` excluded) and body. Sixteen invocations were compared: fourteen
had identical status and body, fifteen had identical headers. The differences are the registered
server-level ones (304 keeps `Content-Type`; a 600 status line renders `<none>`), and the template
case differed only because each binary bound a different ephemeral port. Raw results:
`/root/caddy-rs/.scratch/logs/t-cli-008-diff/diff.json`.

`/root/caddy-rs/.scratch/logs/t-cli-008-diff/diff2.py` covers port ranges, Unix sockets, access
logging and rejection paths (`diff2.json`):

- `127.0.0.1:8000-8001`: both binaries start two servers and print both bound addresses; each
  server's template body expands to its own `N`, `Port` and `Address`. Caddy prints the two lines
  in map order (observed descending); caddy-rs prints ascending.
- `unix//tmp/<path>`: both print `Server address: /tmp/<path>` and answer `418` with `unix-body`
  over the socket.
- `--access-log`: both emit one `http.log.access` entry for the request; the JSON shape differs
  (registered access-log divergence).
- Rejections: `too many unflagged arguments`, the flag-override message and the header-format
  message are byte-identical in message body (only the log envelope differs).

Additional probes for the rejection fixes (`/root/caddy-rs/.scratch/logs/t-cli-008-reject/`):

- `probe_1xx.py`: Caddy answers `100`/`102`/`199` with the interim response then `200` + body, and
  `103` with the interim response then an empty `200`; caddy-rs exits 1 naming `--status`.
- `probe_listen.py`: Caddy starts for `tcp4/`, `tcp6/`, `udp4/`, `udp/`, `unixpacket/` and
  `unix/relative.sock`; it exits 1 for `unixgram/` and `fd/3`. caddy-rs now starts for the
  TCP-family prefixes (same TCP listener Caddy ends up with), rejects relative Unix paths and
  `unixpacket`/`unixgram`/`fd/` with located errors.
- `probe_unixpacket.py`: a STREAM client against Caddy's `unixpacket` socket fails with
  `EPROTOTYPE`; caddy-rs does not pretend a stream socket is seqpacket.
- `probe_headers.py`: Caddy serves 200 and sanitizes CR/LF to spaces, writes other control bytes
  through, and drops `Bad Header`; caddy-rs serves 200, sanitizes CR/LF and control bytes to
  spaces, and drops invalid field names.
- `probe_limits.py`/`probe_limits2.py`: read-header timeout (11–12 s late header closes in both),
  idle timeout (both closed before a 35 s follow-up), and the 12,000/16,000/20,000-byte header
  measurements above.
- `LISTEN_FDS`: an inherited fd 3 with `LISTEN_FDS=1`/`LISTEN_PID=$$` bound to another port makes
  caddy-rs start and serve 200 after `ServerRuntime::without_socket_activation`.

Integration tests: `crates/cli/tests/cli.rs` (`respond_*`) spawn the real binary and assert the
`Server address:` line, status, headers, body, HEAD semantics, stdin, port-range templates, the
access log, socket-activation immunity, the 1xx rejection, header sanitization/drop, the 10 s
read-header timeout, the dropped network prefixes, and every rejected-flag path. Unit tests in
`crates/cli/src/respond.rs` pin listen parsing, argument precedence, header semantics, status
validation, template evaluation and the server-limit fields.

## Proposed register entry (program repository)

```text
## DIV-0118 — `respond` rejects capabilities this build lacks and keeps two runtime gaps

- Area: CLI
- Caddy behaviour: `caddy respond` accepts `--debug` (debug-level internal logging), any integer
  `--status` (1xx is an interim response followed by a final 200; outside 100-999 Go panics per
  request), `unix/relative.sock`, `unixpacket/`/`unixgram/` Unix socket types, `fd/` activation,
  Unix socket permission suffixes, Go's full `text/template`, and a 10 KiB `MaxHeaderBytes`
  (16,000-byte request head -> 431). It ignores `LISTEN_FDS` for this command.
- caddy-rs behaviour: `--debug` exits 1 naming the flag; `--status` outside 200-999 (including
  1xx) exits 1 naming `--status` and the accepted range; relative Unix paths,
  `unixpacket`/`unixgram`, `fd/` and permission suffixes exit 1 naming `--listen`; template
  expressions other than `{{.N}}`/`{{.Port}}`/`{{.Address}}` exit 1 naming the body source.
  `tcp4/`, `tcp6/`, `udp/`, `udp4/` and `udp6/` are accepted and map to the same plain TCP
  listener Caddy ends up with; `respond` ignores `LISTEN_FDS`; the 10 s read-header and 30 s idle
  timeouts are applied. Residual runtime gaps: `max_header_bytes` is set to 10240 but acts as
  hyper's read-buffer cap (16,000-byte head -> 200 where Caddy returns 431; 12,000 and 20,000
  match), and control bytes in header values other than CR/LF become spaces where Go writes them
  through.
- Rationale: This build has no debug-level internal logging, no Go template engine, no interim
  response plumbing and no SOCK_SEQPACKET/SOCK_DGRAM HTTP listener. Silent acceptance would claim
  capabilities that do not exist; `respond` is a development tool, so a located error is a valid
  outcome, and the remaining runtime gaps are measured and registered rather than claimed as
  parity.
- Status: divergent
- Tracking: T-CLI-008
- Test: `crates/cli/tests/cli.rs` `respond_rejects_debug_with_a_located_error`,
  `respond_rejects_interim_1xx_statuses_with_a_located_error`,
  `respond_ignores_systemd_socket_activation`,
  `respond_accepts_the_network_prefixes_caddy_drops`,
  `respond_sanitizes_header_values_and_drops_bad_names_like_caddy`,
  `respond_applies_caddys_read_header_timeout`,
  `respond_rejects_invalid_headers_arguments_and_templates`;
  `crates/cli/src/respond.rs` unit tests.
```
