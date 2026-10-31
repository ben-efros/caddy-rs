# caddy-rs (implementation repository)

The Rust implementation of the caddy-rs program: a Caddy-compatible web server, reverse proxy,
and configuration engine. **Status: M0/M1 skeleton** — the crates compile, 100 tests pass, and the
Caddyfile adapter matches Caddy v2.11.7's golden output for a curated directive subset (30 of the
245 upstream adapter fixtures exactly; see the program repository's conformance report).

See the program repository (`..`) for the plan, compatibility contract, divergence register, and
work queue.

## What works today

- Caddy JSON configuration model with lossless round-tripping and located validation errors
- Immutable configuration generations, atomic reload, in-flight draining
- Module registry (handlers, matchers, storage, issuers, DNS providers) with honest membership
- Caddyfile lexer/parser/adapter: `respond`, `redir`, `file_server`, `root`, `method`,
  `reverse_proxy` (basic options), `header` (simple forms), `encode`, `route`, `handle`,
  `handle_path`; matchers `host`, `path`, `method`, `header`, `query`, `not`, `path_regexp`
  (validation-only), named matchers, global options; exact parity with 6 upstream golden fixtures
- HTTP/1.1 + cleartext HTTP/2 (h2c) serving over TCP and Unix sockets
- Route evaluation with matcher sets, terminals, groups, subroutes, header middleware
- Static file serving with traversal protection, index files, browse, pass_thru
- Reverse proxy: round-robin/first/least-conn balancing, retries, passive health + active health
  checks, forwarded headers, request/response header rewriting
- Admin API: `GET /config/`, `GET /config/<path>`, `POST /load`, `POST /stop`; `/metrics` returns
  an explicit 501 until the observability workstream lands
- TLS foundations: certificate model/cache/SNI, pluggable storage (memory + filesystem), issuer
  traits, renewal queue (ACME/internal issuance is M5 and fails loudly)
- CLI: `version`, `list-modules`, `adapt`, `validate`, `run`, `reload`, `stop`

## What does not work yet (registered, not hidden)

TLS termination, ACME issuance, DNS-01, HTTP/3, dynamic upstreams, placeholder expansion, plugin
loading, request body limits, compression, `/adapt` endpoint, `GET /id/<id>`, partial config
patches, access logging, metrics. Each is tracked in the program plan; behaviour-level gaps are in
the program repository's divergence register.

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
