# WebAssembly plugin host ABI

This document defines version 1.0 of the host ABI for modules embedded in the caddy-rs process. The
out-of-process counterpart is the [external module protocol](PLUGIN-PROTOCOL.md), which reuses this
document's framing, payload encoders, capability model and error codes. For an overview of both
module shapes, see [PLUGINS.md](PLUGINS.md); module authors should start with the
[author guide](PLUGIN-DEVELOPMENT.md). This document is the normative contract.

Third-party extensions use WebAssembly plugins through this versioned ABI. Caddy's Go plugin ABI
and arbitrary native Caddy plugins remain out of scope: a plugin can only do what its descriptor
requests and the operator's capability policy grants.

The reference implementation is the `caddy-rs-plug` crate (`crates/plug`): `caddy_rs_plug::wasm`
provides the in-process Wasmtime runtime (`wasm-runtime` feature, on by default), and
`caddy_rs_plug::protocol` defines the external protocol.

## Version negotiation

The ABI is versioned `major.minor` (`AbiVersion`, `ABI_VERSION` = 1.0). Major versions are
incompatible and must match exactly; minor versions are additive, so the host minor must be greater
than or equal to the plugin's target minor. A zero major version is invalid. Every mismatch is a
typed `NegotiationError` (`HostMajorNewer`, `PluginMajorNewer`, `PluginMinorNewer`, `InvalidVersion`)
and a plugin is never loaded speculatively.

## Capabilities (deny by default)

| Code | Capability | Grants |
|---|---|---|
| 1 | `log` | emit host log messages |
| 2 | `clock` | read the host clock |
| 3 | `random` | draw host randomness |
| 4 | `http_client` | make outbound HTTP requests through the host call |
| 5 | `config_read` | read an immutable snapshot of the plugin's own configuration generation |

A plugin requests raw capability codes in its untrusted descriptor; the host grants them only from
an explicit operator `CapabilityPolicy` (deny-all by default). Unknown codes, duplicates,
over-limit requests and ungranted capabilities are rejected rather than ignored.

## Descriptors and limits

`PluginDescriptor` is untrusted input: name, ABI version, requested capability codes and mandatory
positive limits (body, memory, host calls) that must stay within the ABI hard caps. `validate()`
rejects malformed names/versions/limits; `negotiate(host, policy)` is the single entry point and
returns the effective version, granted capability set and limits.

## Host calls

Stable host-call codes (`log`, `now`, `random`, `http_request`, `read_config`) each require a
capability. `HostCallContext::authorize` checks, in order: the instance's generation is current
(stale generations are rejected after a reload), the capability is granted, the arguments respect
their limits, and the per-request host-call budget allows the call (the budget is consumed only on
success). `read_config` returns an immutable snapshot of the plugin's own generation, never the live
config of a newer one.

## HTTP bridging

Request and response heads carry method, URI, headers and a body mode (`Empty`, `Buffered { len }`,
`Streamed`). Streaming bodies cross the boundary as chunk/end frames with trailers, in the stable
frame layout `tag:u8 | len:u32 | payload`. Limits are enforced per frame (1 MiB), per chunk (64 KiB),
per header set (128 headers, 256-byte names, 8 KiB values), per URI (8 KiB) and for announced body
totals (64 MiB, with `BodyBudget` negotiating the total). Protocol errors use stable `AbiErrorCode`
values (1000–1007); unknown tags, codes, methods, body modes and log levels are typed errors, never
silently skipped.

## In-process runtime and calling convention

The framing rules above are independent of how bytes cross the guest boundary. The reference
runtime (`caddy_rs_plug::wasm::WasmRuntime`) defines the following minimum convention. The frame
encodings are unchanged: request and response payloads are still the `BridgeFrame` tags and bytes
described in this document.

### Guest interface (normative for this runtime)

A guest core-WASM module MUST export:

| Export | Type | Meaning |
|---|---|---|
| `memory` | linear memory | all buffers exchanged with the host |
| `alloc(len: u32) -> u32` | function | reserve `len` bytes, return the pointer |
| `handle_request(ptr: u32, len: u32) -> i64` | function | process a request-frame buffer, return a response-frame buffer |

and MAY import exactly one host function:

| Import | Type | Meaning |
|---|---|---|
| `caddy.host_call(call_ptr: u32, call_len: u32, out_ptr: u32, out_len: u32) -> i64` | function | perform a capability-gated host call |

`handle_request` receives a sequence of request `BridgeFrame`s (`REQUEST_HEAD`, zero or more
`REQUEST_BODY_CHUNK`, `REQUEST_END`). It returns a packed `i64`:

* **non-negative**: `(response_ptr << 32) | response_len`, pointing at response `BridgeFrame`s
  (`RESPONSE_HEAD`, zero or more `RESPONSE_BODY_CHUNK`, `RESPONSE_END`) in guest memory;
* **negative**: `-(AbiErrorCode)` (for example `-1000` for `capability_denied`), which fails the
  invocation with that stable code.

`host_call` receives an encoded `HostCall` payload and an output buffer. It returns the encoded
`HostCallResult` length written to the output buffer, or a negative `AbiErrorCode`. Calls are
authorised against the negotiated capabilities, generation, argument limits and per-request budget
before dispatch; denial returns `-1000` and the guest decides whether the request can continue.

The host validates every response frame, the declared body mode/length, body limits and the
presence of exactly one head and one end before exposing a response to the HTTP layer. Unknown
imports, missing exports or malformed frames fail with a typed `WasmError`. This build does not link
WASI, so guest modules have no ambient filesystem, network or clock access.

### Runtime limits (normative defaults; host-configurable)

| Limit | Mechanism | Default | Failure |
|---|---|---|---|
| Fuel | `Config::consume_fuel(true)`; reset with `Store::set_fuel` per request | 10,000,000 fuel | `WasmError::FuelExhausted` → `limit_exceeded` (1002) |
| Wall clock | epoch interruption; one-shot timer increments the engine epoch | 5 s | `WasmError::Timeout` → `cancelled` (1005) |
| Memory | `StoreLimits` store limiter (`memory_size`, `instances`) | 64 MiB, 1 instance | trap/instantiation → `plugin_failed` (1007) |
| Module size | host byte-length check before compilation | 16 MiB | `WasmError::ModuleTooLarge` → `invalid_request` (1003) |
| Request/response body | host checks before/after guest execution | 64 MiB each | `WasmError::LimitExceeded` → `invalid_request`/`limit_exceeded` |

A limit failure fails only that invocation/session; the host process and other plugins continue.
Fuel is deterministic (per-request reset); the wall-clock deadline is a safety net, not a
deterministic execution bound. Host-call implementations can be injected (`HostCallProvider`). The
default provider implements `log`, `now`, `random` (Unix `/dev/urandom`) and `config_read` (returns
`None`), and returns a typed `host_failure` for `http_client`; an operator-supplied provider is
required for outbound HTTP.

### Implementation boundaries

| Area | In this build |
|---|---|
| Core WASM modules, fuel, epoch timeout, memory/body/module limits | supported |
| ABI frames, descriptors, capabilities, host calls | supported (without WASI) |
| Guest languages via core-WASM compilation | compiled by the guest toolchain, not by this crate |
| WASI preview1/preview2, sockets, filesystem, clocks | not available: this build links no WASI |
| Component model | not accepted: core modules only |
| SIMD, bulk memory, reference types | enabled in the engine config; guest use is optional |
| Async host calls and streaming host-call HTTP | not part of ABI v1: calls are buffered and synchronous |
| `http_client` host call | requires an injected provider; the default provider returns a typed host failure |
| Deterministic wall clock | not provided: fuel is deterministic, time is a safety net |

## Runtime overhead and caching (benchmarked offline)

The WASM host runtime (`crates/plug/src/wasm.rs`, `wasm-runtime` feature) has a deterministic
offline benchmark:
`cargo test --offline --locked -p caddy-rs-plug --test bench -- --nocapture`.
Representative medians and p95 values from the reference host:

| operation | median | p95 |
|---|---:|---:|
| in-process module compile (WAT -> native) | 5.75 ms | 11.6 ms |
| fresh Store/instance | 122 us | 142 us |
| request on a reused instance (incl. per-request watchdog) | 82 us | 121 us |
| request with instantiate + handle | 273 us | 360 us |
| external process spawn + handshake | 6.2 ms | 6.7 ms |
| external frame round-trip | 25 us | 47 us |

Absolute timings depend on the host; the values above document the order of magnitude and the
relative costs. Caching contract: compile the module once and reuse the `WasmRuntime` for the
plugin/generation lifetime (the runtime owns the compiled `Module` and deterministic `Engine`);
spawn one external `HostService` per generation. Do not compile per request.

Instance pooling is intentionally not provided: every checkout must be a clean Store/instance
because linear memory, globals, fuel and the host-call budget are request state, and
re-instantiation is the reset. The host resets fuel/epoch before every request and never reuses
guest memory across requests. A failed or poisoned instance is discarded and a fresh one is
created; no instance is ever reused after an error.

## External module protocol (out-of-process modules)

The ABI above is the contract for modules embedded in the host process. Modules may also run
outside the process; that path uses the [external module protocol](PLUGIN-PROTOCOL.md), implemented
by `caddy_rs_plug::protocol`:

- the same frame layout (`tag: u8 | len: u32 | payload`), the same payload encoders for HTTP heads,
  headers, chunks, trailers, host calls, host-call results and ABI error frames, and the same
  little-endian bounds-checked encodings — there is no second framing or encoding family;
- a handshake (`HELLO`/`HELLO_ACK`/`REJECT`) that negotiates the external protocol version and the
  plugin ABI version with the same `AbiVersion` rules, validates the untrusted descriptor, and
  grants capabilities from the operator allow-list (deny-by-default) — the ACK carries the exact
  granted set, effective limits and backpressure window bounds;
- request multiplexing with non-zero `RequestId`s (`OPEN_REQUEST` with an optional deadline, body
  chunks/end, response head/chunks/end), capability-gated `HOST_CALL`/`HOST_CALL_RESULT` frames,
  `CANCEL`, and request-scoped or fatal `ERROR` frames mapped to the stable `AbiErrorCode` values;
- in-process ABI frame tags `1..=9` and unknown tags are rejected on the external protocol; the
  external protocol uses the reserved `0x10..=0x2C` range.

Host lifecycle and process isolation for external modules are implemented by
`caddy_rs_plug::host`: it spawns or connects the process, performs the handshake, routes
capability-gated host calls, scopes the service to a configuration generation through
`caddy_rs_core::GenerationResource`, and stops it with a bounded grace period (fatal close → wait
→ kill → reap) or isolates and reports a crash with an explicit restart policy (no silent restarts
by default). Both paths share the same capability, limit and error model, so a host runtime can
route either a WASM instance or an external process through one session contract.

## Encoding and security invariants

- Little-endian, `u32` length-prefixed fields, bounds-checked readers (EOF, limits, UTF-8, trailing
  bytes), no padding.
- No ambient filesystem, network, clock or randomness access; outbound HTTP only through the
  capability-gated host call.
- No shared memory and no raw pointers: everything crosses the boundary as encoded bytes
  (`#![forbid(unsafe_code)]`).
- A malformed frame or payload is a typed error and can never panic the host.

## Non-goals

- Caddy/Go plugin compatibility.
- A WASM runtime, fuel metering or instantiation logic outside the `wasm-runtime` feature.
- A manifest file format: descriptors are data and the ABI types are serde-serializable, but this
  crate defines no manifest syntax.

## Evidence

The crate's tests are the executable form of this contract.

- `cargo test --offline --locked -p caddy-rs-plug` runs the unit tests in `crates/plug/src` and the
  integration suites in `crates/plug/tests`:
  - `abi.rs`: version negotiation and mismatch rejection, capability grants and rejections,
    descriptor validation, host-call authorisation and budgets, bridge frame round-trips, body
    accounting and malformed-input rejection.
  - `protocol.rs`: golden frame layouts, handshake accept/reject cases, the in-process module echo
    driver, cancellation and malformed-input checks.
  - `host.rs`: real child processes over stdio, handshake success and rejection, request
    round-trips, capability denial surfaced to the module, generation stop with reaping, crash
    isolation, no-zombie checks, oversized-frame rejection and restart policy.
  - `authoring.rs`: the documented `author_module` example through the reference host, plus
    docs-vs-code consistency checks for capabilities, host calls and error codes.
  - `template.rs`: builds `crates/plug/template` in its own workspace and runs the built binary
    through the host.
  - `wasm.rs`: WAT guests echoing through the ABI, fuel exhaustion, epoch timeout, denied host
    calls and ungranted capability declarations.
  - `hardening.rs`: pathological guests (unbounded growth, oversized minimum memory, host-call
    spam, enormous declared response lengths, traps and timer leaks).
  - `bench.rs`: the offline overhead report; run with `--nocapture` to print the numbers.
- `cargo check -p caddy-rs-plug --no-default-features` verifies the protocol-only build.
