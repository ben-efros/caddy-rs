# caddy-rs (implementation repository)

Hosted at <https://github.com/ben-efros/caddy-rs>.

The Rust implementation of the caddy-rs program: a Caddy-compatible web server, reverse proxy,
and configuration engine. **Status: M2/M5 (post wave-4/5 sprint)** — the crates compile, **1036 tests pass**, HTTPS
termination, **default-on automatic HTTPS** (fake-CA/offline tested, per-server controls and
non-standard-port derivation), renewal hot-swap, streaming responses and request bodies,
forward_auth, WebSocket/Upgrade passthrough, HTTP/2+h2c upstreams, PKI/trust, admin ETag
preconditions/`/adapt`/`/reverse_proxy/upstreams`, and runtime metrics/access-log emission work end
to end, and the Caddyfile adapter matches Caddy v2.11.7's golden output for every fixture it supports:
**84 of the 245 upstream adapter fixtures exactly, 0 mismatches** (100% of supported fixtures, 34.3%
corpus coverage). A real Caddy v2.11.7 binary oracle is acquired and run by the program repository.
See the program repository's conformance report.

See the program repository (`..`) for the plan, compatibility contract, divergence register, and
work queue.

## What works today

- Caddy JSON configuration model with lossless round-tripping and located validation errors, typed
  logging/storage/TLS-app models, and module-reference validation
- Immutable configuration generations, atomic reload, in-flight draining; generation-scoped
  supervisor that reuses unchanged listeners and rebinds changed ones
- Module registry (handlers, matchers, logging/TLS config modules, storage, issuers, DNS providers)
  with an honest executing/config-only/reserved distinction
- Caddyfile lexer/parser/adapter: `respond`, `redir`, `file_server`, `root`, `method`,
  `reverse_proxy` (unix upstreams, balancing, retries, health options, HTTP/2+h2c transports,
  WebSocket/Upgrade passthrough), `header`, `encode`, `route`, `handle`, `handle_path`,
  `forward_auth`; matchers `host`, `path`, `method`, `header`, `query`, `not`, `path_regexp`
  (config-only); heredocs, line continuation, same-file snippets/imports with arguments, named
  routes and `invoke` JSON, `request_body`, `try_files`, `uri`, `bind` and plain `log` directives;
  global options (including global ports); 84 exact upstream golden fixtures
- HTTP/1.1 + cleartext HTTP/2 (h2c) over TCP and Unix sockets; **HTTPS termination** via rustls with
  SNI (exact/wildcard), ALPN h2/http1.1, TLS versions and client-auth request/require;
  **automatic HTTPS** for explicit `apps.tls` automation: ACME issuance (HTTP-01, DNS-01,
  TLS-ALPN-01) and internal CA, challenge listeners, 308 redirects, two-phase apply with rollback,
  generation-scoped renewal with resolver hot-swap; dual-stack wildcard listeners; per-server
  timeouts, header/body limits, connection caps and systemd socket activation
- Route evaluation with matcher sets, terminals, groups, subroutes, header middleware and the
  placeholder engine (request/vars/env/header placeholders in rewrite/respond/headers/vars)
- Static file serving with traversal protection, index files, browse, pass_thru
- Reverse proxy: HTTP, HTTPS (rustls with explicit/system trust, insecure opt-in, SNI) and
  Unix-socket upstreams, round-robin/first/least-conn balancing, retries with retry_match, active +
  passive health checks, forwarded headers and trusted proxies, request/response header rewriting,
  streaming responses (no full-body buffering; mid-stream errors and client cancellation handled),
  **WebSocket/Upgrade passthrough** (h1, cleartext+TLS), **HTTP/2 and h2c upstreams**
  (`transport.versions`), canonical forward_auth execution (rewrite/handle_response, header copy,
  401/403 pass-through); request bodies stream end to end with retry-capable buffering; h2
  upstreams send the request Host as `:authority`
- Admin API: `/config/` traversal, full `POST/PUT/PATCH/DELETE` partial updates with validation
  and rollback, `/id/<id>`, ETag and `If-Match`/`If-None-Match` config preconditions, `/load`,
  `/stop` (exits the process for all adapters), `POST /adapt`, `GET /reverse_proxy/upstreams`,
  origin enforcement, `/metrics` Prometheus text endpoint, access-log
  record/redaction/sampling/sink primitives and Caddy `logging.logs[]` mapping
- TLS/ACME: certificate model/cache/SNI, Caddy/CertMagic storage layout, ACME directory/account/
  order/CSR/transport clients, `AcmeIssuer` issuance with HTTP-01/DNS-01/TLS-ALPN-01 solvers,
  config-constructed Cloudflare DNS-01 provider with DNS-over-HTTPS propagation checks
  (mock-tested), Caddy-compatible internal CA (`tls internal`), Caddyfile `tls` directive/global
  ACME options, automatic-HTTPS driver for explicit automation and renewal schedulers
- Middleware/engine: placeholder engine, forward_auth and basic_auth/authentication handlers,
  streaming response/request-body engine, request/response header rewriting, static/file serving,
  vars handler, same-file snippet/import expansion, async generation lifecycle hooks
- PKI/observability: read-only `/pki` endpoints + `pki list/export/trust` CLI, Prometheus metrics
  and Caddy `logging.logs[]`-configured access-log emission at runtime
- Acceptance: local acceptance harness (forward_auth/Authelia, streaming, WebSocket, TLS, internal
  CA auto-HTTPS, admin) and Pebble real-ACME acceptance (HTTP-01/TLS-ALPN-01, account reuse)
- Compatibility: real Caddy v2.11.7 oracle acquisition (no Docker), adapt/validate/runtime probes,
  drift triage and nightly workflow; 80 registered divergences with tracking tasks
- CLI: `version`, `list-modules`, `adapt`, `validate`, `run`, `reload`, `stop`

## What does not work yet (registered, not hidden)

Live ACME/Cloudflare-DNS-01 validation (client logic is mock/Pebble-tested; needs real credentials),
the remaining default-on automatic-HTTPS derivation edges (mixed listener ports, multiple
non-standard HTTPS ports, on-demand TLS, ARI), HTTP/3/QUIC, gzip/zstd compression, `templates`,
generic `handle_response`/error routes, remaining `map`/global-`log`/rewrite operations,
FastCGI/`php_fastcgi`, dynamic upstreams, PROXY protocol, the WASM/plugin ABI, the file matcher for
`try_files`, HTTP/2 extended CONNECT, WebSocket close-frame semantics, per-server access-log
association, and full TLS client-auth policy. Behaviour-level gaps are the divergence register
(80 entries).

## Workspace map

| Crate | Workstream | Responsibility |
|---|---|---|
| `caddy-rs-core` | WS-01 core runtime | JSON config model, module registry, validation, generation lifecycle |
| `caddy-rs-config` | WS-06 configuration | Caddyfile lexer/parser/adapter to Caddy JSON |
| `caddy-rs-http` | WS-02/05 HTTP + routing | matchers, handlers, route tree, static/file serving |
| `caddy-rs-proxy` | WS-03 reverse proxy | upstreams, balancers, retries, health checks, proxy handler |
| `caddy-rs-tls` | WS-04 TLS | certificate storage abstraction, cache, SNI selection, renewal scheduling, issuer traits |
| `caddy-rs-admin` | WS-07 admin API | `/load`, `/config/`, `/stop` over the admin endpoint |
| `caddy-rs-server` | WS-01/02 runtime | listener management, hyper HTTP serving, generation-aware reload |
| `caddy-rs` (crates/cli) | WS-01 | `adapt`, `validate`, `run`, `reload`, `stop`, `list-modules`, `version` |

## Build

The sandbox that authored this tree cannot write to the crates.io cache, so the build is offline
and uses `vendor/httpdate` via `[patch.crates-io]`:

```sh
cargo build --offline --workspace
cargo test --offline --workspace
```

For a normal online build, remove the `[patch.crates-io]` section from `Cargo.toml`.

## Documentation

- `docs/DESIGN.md` — architecture and decisions the code encodes
- `docs/TESTING.md` — test layers and rules
- Program repository `../docs/` — compatibility contract, divergences, ADRs, planning hierarchy

## License

Apache-2.0, matching Caddy. See `LICENSE` and `NOTICE.md`.
