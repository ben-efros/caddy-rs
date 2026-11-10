# T-CLI-008 compatibility note — `caddy-rs respond`

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task adds the `respond` subcommand. For the documented cases it produces the same HTTP responses as
Caddy v2.11.9; the differences are the CLI-wide diagnostic envelope (DIV-0023), the server-level
`Server: Caddy`/header-case/access-log-format differences already registered for the runtime, and
the unsupported capabilities below, which fail loudly. The proposed register text is at the end of
this note.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- `modules/caddyhttp/staticresp.go` — `respond` command registration (`init`): the usage string,
  `-l/--listen` (default `:0`), `-s/--status` (default 200), `-b/--body`, `--access-log`,
  `-v/--debug`, `-H/--header` (`StringArray`), and the long help text.
- `modules/caddyhttp/staticresp.go::cmdRespond` — argument/flag precedence, stdin body
  (`os.ModeNamedPipe`), header parsing (`Field: value` via `strings.Cut` + `TrimSpace` +
  `http.Header.Set`), `ParseNetworkAddress` and port-range expansion, per-server
  `buildHTTPServer`, admin disabled + `config.persist=false`, and the `Server address:` output.
- `modules/caddyhttp/staticresp.go::buildHTTPServer` — the body template context
  (`{{.N}}`/`{{.Port}}`/`{{.Address}}`), the `static_response` handler, the 10 s read-header and
  30 s idle timeouts, 10 KiB max header bytes, `AutoHTTPS.DisableRedir`, and `logs` for
  `--access-log`.
- `modules/caddyhttp/staticresp.go::StaticResponse.ServeHTTP` — status default 200, configured
  header application, implicit `Content-Type` (`application/json` for a valid JSON object/array,
  otherwise `text/plain; charset=utf-8`) only when the body is non-empty and no `Content-Type` is
  set, and body suppression for 1xx/204/304 by the Go HTTP server.
- `listeners.go::ParseNetworkAddress`/`SplitNetworkAddress` — network prefix, omitted port,
  inclusive port ranges.

## Implemented behaviour

`crates/cli/src/respond.rs` builds an in-memory `caddy_rs_core::Config` with `admin.disabled =
true`, `admin.config.persist = false`, one `static_response` route per server, and runs it through
the same `GenerationStore`/`ServerRuntime` as `caddy-rs run`. It prints the actual bound address(es)
as `Server address: <addr>` and blocks until `SIGINT`/`SIGTERM`.

| Input | Result |
|---|---|
| `respond` | `:0` (dual-stack, random port), empty 200, prints the bound address |
| `respond 404` | 404, empty body |
| `respond hello` | 200, body `hello`, `text/plain; charset=utf-8` |
| `respond --status 200 404` | 200, body `404` |
| `respond --body '{"a":1}'` | `application/json` |
| `respond --header "X-Test: yes"` | response header `X-Test: yes`; repeated fields replace |
| `respond -l 127.0.0.1:8000-8001` | one server per port, each printed |
| `respond -l unix//tmp/x.sock` | plain HTTP over the Unix socket |
| `respond < file` | stdin is **not** read (regular file, matching `os.ModeNamedPipe`) |
| `echo x \| respond` | body from stdin |
| `respond --access-log` | access entries on stderr (this build's access-log JSON) |
| `respond --debug` | exit 1, located error naming `--debug` |
| `--status 99` / `--status 1000` | exit 1, located error naming `--status` |
| `--listen udp/:0` / `--listen fd/3` | exit 1, located error naming `--listen` |
| two unnamed arguments | exit 1, `too many unflagged arguments` |
| `--status`+`--body`+unnamed argument | exit 1, `unflagged argument "<arg>" is overridden by flags` |
| `--header` without `Field: value` | exit 1, Caddy's `header <i>: invalid format ...` |
| a template other than `{{.N}}`/`{{.Port}}`/`{{.Address}}` | exit 1, located error naming the body source |

Argument precedence reproduces Caddy exactly, including its `os.Args` check: an unnamed 3-digit
numeric argument is the status only when the literal string `--status` is absent from `argv`, so
`--status=404 200` behaves like Caddy (the argument wins) and `-s 201 404` behaves like Caddy (the
argument wins). Numeric arguments outside 100-999 are ignored rather than used as a body, also
matching `cmdRespond`'s `Atoi` branch.

## Divergences from Caddy v2.11.9

| Area | Caddy v2.11.9 | caddy-rs | Why |
|---|---|---|---|
| `--debug` | accepted; raises the default log level to DEBUG and emits internal debug logs | exit 1 with `--debug is not supported by this build ...` | This build has no debug-level internal logging. Silently accepting the flag would claim a capability it does not have; `respond` is a development tool, so a located error is the honest result. |
| `--status` outside 100-999 | accepted; the server starts and Go panics per request (`invalid WriteHeader code`) | exit 1 at startup naming `--status` | A per-request panic is not a useful behaviour to reproduce; fail-closed at startup is strictly safer and still loud. |
| `--listen udp/...` | the network prefix is dropped by `JoinHostPort`, so Caddy silently serves **TCP** on the port | exit 1 naming `--listen` | Silently changing the transport is worse than rejecting; `respond` serves plain HTTP/1.1 over TCP or Unix sockets. |
| `--listen fd/...` | systemd socket-activation descriptors | exit 1 naming `--listen` | Not implemented for this command. |
| Unix socket permissions (`unix//path\|0666`) | applied | exit 1 naming `--listen` | Not implemented by the listener. |
| body template | full Go `text/template` | only `{{.N}}`, `{{.Port}}`, `{{.Address}}`; anything else is a located error | A Go template engine is not available; rejecting unsupported expressions keeps the limitation loud. |
| port-range output order | Go map iteration, unspecified | configured port order | Deterministic output is a superset of Caddy's contract; the addresses themselves are identical. |
| `--header` field names | canonical `X-Test` | lower-case `x-test` | The Rust HTTP stack lower-cases field names; HTTP/1.1 field names are case-insensitive (server-level, already registered). |
| `Server: Caddy` | set on every response | not set | Already registered for the server runtime (DIV-0016 residual). |
| 304 with a body | Go strips `Content-Type` | `Content-Type` is kept | Server-level (hyper does not apply Go's 304 header stripping); the status line and empty body match. |
| status 600 reason phrase | `600 status code 600` | `600 <none>` | Server-level status-line rendering for non-standard codes. |
| access-log format | Caddy's `http.log.access` JSON with `Server: Caddy` in `resp_headers` | this build's access-log JSON | Already registered access-log divergence; `--access-log` reuses it rather than inventing a second sink. |
| error envelope | zap JSON log line | `caddy-rs: error: <message>` | CLI-wide DIV-0023. |

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
(normalized; `Date` and `Server` excluded) and body. Sixteen invocations were compared; fourteen
matched exactly (status, body and every header except `Server`), including the default empty 200,
text and JSON bodies, 404, custom headers, `Content-Type` override, HEAD, positional status/body,
`--status 201 404`, stdin, and 204. The remaining two are the registered server-level differences
above: 304 keeps `Content-Type` and a 600 status line renders `<none>`. Raw results:
`/root/caddy-rs/.scratch/logs/t-cli-008-diff/diff.json`.

`/root/caddy-rs/.scratch/logs/t-cli-008-diff/diff2.py` covers port ranges, Unix sockets, access
logging and rejection paths (`diff2.json`):

- `127.0.0.1:8000-8001`: both binaries start two servers and print both bound addresses; each
  server's template body expands to its own `N`, `Port` and `Address` (`n=0 port=8000 ...` /
  `n=1 port=8001 ...`). Caddy prints the two lines in map order (observed descending); caddy-rs
  prints ascending.
- `unix//tmp/<path>`: both print `Server address: /tmp/<path>` and answer `418` with `unix-body`
  over the socket.
- `--access-log`: both emit one `http.log.access` entry for the request; the JSON shape differs
  (registered access-log divergence).
- Rejections: `too many unflagged arguments`, the flag-override message and the header-format
  message are byte-identical in message body (only the log envelope differs). `--debug`,
  `udp/:0` and `--status 99` are the loud caddy-rs rejections listed above.

Integration tests: `crates/cli/tests/cli.rs` (`respond_*`) spawn the real binary and assert the
`Server address:` line, status, headers, body, HEAD semantics, stdin, port-range templates, the
access log, and every rejected-flag path. Unit tests in `crates/cli/src/respond.rs` pin listen
parsing, argument precedence, header semantics, status validation and template evaluation.

## Proposed register entry (program repository)

```text
## DIV-0117 — `respond` rejects `--debug` and other capabilities this build lacks

- Area: CLI
- Caddy behaviour: `caddy respond` accepts `--debug` (debug-level internal logging), any integer
  `--status` (Go panics per request outside 100-999), `udp/`/`fd/` listen networks, Unix socket
  permission suffixes, and evaluates the body with Go's full `text/template`.
- caddy-rs behaviour: `--debug` exits 1 with a located error naming the flag; `--status` outside
  100-999 exits 1 naming `--status`; `udp/`/`fd/`/permission-suffix listens exit 1 naming
  `--listen`; template expressions other than `{{.N}}`, `{{.Port}}` and `{{.Address}}` exit 1
  naming the body source. All other documented `respond` flags, argument precedence, status/body/
  header semantics and the `Server address:` output match Caddy.
- Rationale: This build has no debug-level internal logging, no Go template engine and a plain
  HTTP/1.1 listener. Silent acceptance would claim capabilities that do not exist; `respond` is a
  development tool, so a located error is a valid outcome.
- Status: divergent
- Tracking: T-CLI-008
- Test: `crates/cli/tests/cli.rs` `respond_rejects_debug_with_a_located_error`,
  `respond_rejects_invalid_headers_arguments_and_templates`;
  `crates/cli/src/respond.rs` unit tests.
```
