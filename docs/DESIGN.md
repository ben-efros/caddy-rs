# caddy-rs design notes

This document describes how the implementation is put together: the crate graph, the
configuration and request lifecycles, and the decisions the code encodes.

## Crate graph

```
                    ┌────────────────────────────┐
                    │        caddy-rs (bin)      │
                    │ adapt validate run reload  │
                    └───────────┬────────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        │                       │                        │
┌───────▼────────┐   ┌──────────▼─────────┐   ┌──────────▼─────────┐
│ caddy-rs-server│   │  caddy-rs-admin    │   │ caddy-rs-config    │
│ listeners      │   │ /load /config /stop│   │ Caddyfile → JSON   │
│ hyper serving  │   └──────────┬─────────┘   └──────────┬─────────┘
│ supervisor     │              │                        │
└───┬────────┬───┘              │                        │
    │        │                  │                        │
    │   ┌────▼─────────┐        │                        │
    │   │ caddy-rs-proxy│       │                        │
    │   │ upstreams     │       │                        │
    │   │ balancers     │       │                        │
    │   │ retries/health│       │                        │
    │   └────┬──────────┘       │                        │
    │        │                  │                        │
    │   ┌────▼─────────┐        │                        │
    │   │ caddy-rs-http │       │                        │
    │   │ matchers      │       │                        │
    │   │ handlers      │       │                        │
    │   │ router        │       │                        │
    │   └────┬──────────┘       │                        │
    │        │                  │                        │
    │   ┌────▼──────────────────▼────────────────────────▼────┐
    │   │                  caddy-rs-core                     │
    │   │ config model · module registry · validation ·      │
    │   │ immutable generations · adapter trait              │
    │   └────────────────────────────────────────────────────┘
    │
┌───▼──────────────┐
│  caddy-rs-tls    │   certificate model/cache · storage trait · issuer trait · renewal queue
└──────────────────┘
```

Dependency direction is one-way. `core` depends on no HTTP/TLS library, which keeps the
configuration contract testable in isolation and lets the Caddyfile adapter be built and tested
before the server exists.

## Configuration generations

A `Config` is decoded, validated, provisioned, and started as one immutable `Generation`
(`crates/core/src/generation.rs`). The `GenerationStore` holds a single `Arc<Generation>` behind an
`RwLock`; requests clone that `Arc` at connection time. Reload builds the replacement generation
first, validates it, and only then swaps the pointer. The old generation is marked `stopping` and is
drained by `drain(&Arc, timeout)`, which waits until all other request handles are dropped.

Listener survival is handled separately from generation lifetime: the runtime reconciles the
listener set on each generation change and reuses listeners whose address did not change
(`crates/server/src/runtime.rs`). That means a reload never creates a listening gap for unchanged
addresses, and an unchanged address is not rebound (avoiding `EADDRINUSE` races).

## Module registry

Handlers and matchers are looked up by both their dotted Caddy module id
(`http.handlers.reverse_proxy`) and their JSON short key (`reverse_proxy`). Validation rejects an
unregistered module with a located error before provisioning. The built-in table is deliberately
conservative: a module is registered only when this build can execute it, so the absence of TLS/ACME
modules is visible at validation time rather than at request time.

Extensions: third-party modules run either as WebAssembly guests inside the host process or as
separate processes speaking the module protocol; the registry remains the single source of truth
for names (`crates/plug`).

## Request flow

1. Listener accept loop (TCP or Unix) acquires the active `Generation` (drain semantics) and the
   router for that listen address.
2. hyper decodes HTTP/1.1 or cleartext HTTP/2; `crates/server/src/http.rs` converts to the internal
   `Request`.
3. `Router` evaluates routes in order: matcher sets (OR between sets, AND within), handler chains,
   `terminal` and `group` semantics.
4. Handlers return either `Continue(request)` or `Respond(response)`. Response middleware (headers)
   stages headers on the request so they apply to whichever later handler writes the response.
5. `reverse_proxy` selects a healthy upstream, rewrites forwarded headers, forwards over hyper's
   client, applies retry/health policy, and returns the upstream response.

## Compatibility strategy

The adapter is tested against Caddy's own `caddyfile_adapt` golden fixtures (curated subset, exact
JSON equality) and locally authored fixtures for the supported subset. See
`crates/config/tests/fixtures/README.md`. Anything not supported fails with a located error naming
the construct; nothing silently degrades to different behaviour.

The compatibility contract and its generated evidence are maintained alongside the project; the
matrix and the numbered divergence register.

## Offline build note

The sandbox that authored this repository cannot write to the crates.io cache and cannot fetch the
`httpdate` crate (a hyper dependency). `vendor/httpdate` implements the small public surface hyper
uses, wired through `[patch.crates-io]`. It is a build-environment workaround, not a design
decision: delete the patch when building online.
