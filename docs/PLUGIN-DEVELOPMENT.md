# Module author's guide

This guide covers ABI v1.0 and external protocol v1.0. It is not a new normative contract: the
binding contracts are [PLUGIN-ABI.md](PLUGIN-ABI.md) (in-process WebAssembly host ABI) and
[PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md) (external module protocol). Where this guide and those
documents disagree, the contracts win. The guide is written so that a third party can build a module
without reading the reference implementation's tests.

Reference implementation: `crates/plug` (crate `caddy-rs-plug`). Runnable example:
[`crates/plug/src/bin/author_module.rs`](../crates/plug/src/bin/author_module.rs); its host test is
[`crates/plug/tests/authoring.rs`](../crates/plug/tests/authoring.rs).

## 1. What a module is

A module is a request transformer (in Caddy terms, a handler, matcher or provider equivalent) that
the host loads and invokes. caddy-rs supports two module shapes, and they share the same
descriptors, capability names, limits, host calls and error codes:

| | **In-process ABI** ([PLUGIN-ABI.md](PLUGIN-ABI.md)) | **External module protocol** ([PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md)) |
|---|---|---|
| Where the code runs | Embedded in the host process, driven through the Wasmtime runtime (`caddy_rs_plug::wasm`, `wasm-runtime` feature, on by default) | A separate OS process, or an operator-provided local socket, driven over stdio/Unix socket |
| Wire unit | `BridgeFrame` tags 1–9, one implicit request at a time | `ProtocolFrame` tags 0x10–0x2C with `RequestId` multiplexing, handshake, deadlines |
| Language | Any language that compiles to the supported WebAssembly target | Any language that can read/write the documented bytes and use a local transport |
| Isolation | WebAssembly sandbox, host-controlled memory/fuel/time | Process/OS isolation configured by the operator (user, container, namespace, seccomp), host-enforced protocol limits |
| Choose it when | You want the tightest latency and the WebAssembly sandbox, and your module is small/CPU-bound | You need native libraries/runtimes, a different OS process boundary, independent restarts, or a language without WebAssembly support |
| In this repository | Runtime implemented behind the default-on `wasm-runtime` feature (`caddy_rs_plug::wasm`) | Protocol and reference host lifecycle implemented (`caddy_rs_plug::host`) |

Both paths use the same **capability** and **error-code** vocabulary. "Deny by default" means the
module receives no capability unless the operator's policy grants exactly that capability and the
module requested it: requesting a capability is a declaration, never an entitlement.

## 2. The development loop

1. **Pick the path** using the table above. If you are unsure, start with the external protocol: its
   reference host and complete example are in this repository, and its lifecycle and host-call
   behavior are the same contract the WASM path uses.
2. **Write the descriptor** (data, not code): a stable module `name`, the plugin ABI version you
   target (`major.minor`; the current version is `1.0`), the raw capability codes you request (keep
   the list minimal), and your requested limits.
3. **Request only capabilities you actually use.** Each one is an operator decision. Missing grants
   must degrade gracefully, not crash the module.
4. **Implement the request loop** (external) or the ABI entry point (in-process). Read the request
   head, then body chunks/trailers, do your work, write a response head/chunks/end. Make host calls
   between request frames when you need a capability.
5. **Run it against a host.** External: use `caddy_rs_plug::host::HostService` (as the example test
   does) or another implementation of [PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md). In-process:
   instantiate the module through `caddy_rs_plug::wasm::WasmRuntime`; `crates/plug/tests/wasm.rs`
   shows the host-side setup.
6. **Test the boundary cases**: denied capabilities, malformed/oversized frames from the peer,
   cancellation/deadline, body limits, crash/restart, and version mismatch.

## 2a. Start from the template

A copyable starter crate lives at [`crates/plug/template/`](../crates/plug/template). It is a
**standalone workspace** (its own `[workspace]` and `Cargo.lock`) with a single path dependency on
`caddy-rs-plug`, so it is not a member of the caddy-rs workspace and does not change the main
`Cargo.lock` or build graph. It implements the minimal external module: `HELLO`/`HELLO_ACK`, one
echo-style request handler, and one capability-gated `log` host call.

```sh
# from the repository root: copy the template next to (not inside) the repository
cp -r crates/plug/template ../my-module

# build it with its own workspace
(cd ../my-module && cargo build)

# from the repository root, build and test the template as shipped
cargo build --offline --locked --manifest-path crates/plug/template/Cargo.toml
cargo test --offline --locked -p caddy-rs-plug --test template
```

Change these first after copying:

1. `Cargo.toml`: `package.name` and `[[bin]] name`; keep `publish = false`; switch the
   `caddy-rs-plug` path dependency to the published version when you distribute the module.
2. `src/main.rs` descriptor: module `name` (stable, operator-visible), `abi` version, the
   **minimal** capability list, and realistic `PluginLimits`.
3. `src/main.rs` request handler: replace the echo body/status with your logic; keep reading
   `OpenRequest`/body chunks/`RequestEnd` and writing response head/chunks/end in order.
4. Host calls: keep the `HelloAck.granted` check and handle `CapabilityDenied` by degrading or
   failing the request with a typed error.
5. Tests: replace the template's trivial behavior assertions with your module's contract tests;
   keep the handshake/deny/limit/crash cases from section 10.

## 3. External process module: complete worked example

The example is [`author_module.rs`](../crates/plug/src/bin/author_module.rs). It is an echo-style
module that handles a streamed request body, makes two host calls, and returns a 200 response with
an `X-Host-Time` header.

Build/run commands:

```sh
# build the example binary
cargo build -p caddy-rs-plug --bin author_module

# run the documented host+module path end to end (real child process, stdio, no network)
cargo test --offline --locked -p caddy-rs-plug --test authoring
```

There is no standalone host binary in this crate; the example binary expects a protocol peer on
stdin/stdout. The integration test is the documented way to run it: it starts `HostService`, grants
`log` and `clock`, sends one request, answers the two host calls, and asserts the echo response and
header.

### 3.1 Handshake

```rust
let hello = Hello {
    protocol: PROTOCOL_VERSION, // external protocol version (1, 0)
    descriptor: PluginDescriptor {
        name: "author-example".to_string(),
        abi: AbiVersion::new(1, 0), // plugin ABI version
        capabilities: vec![Capability::Log.code(), Capability::Clock.code()],
        limits: PluginLimits::default_limits(),
    },
};
write_frame(&mut output, &ProtocolFrame::Hello(hello), &limits)?;
let ack = match read_frame(&mut input, &limits)? {
    ProtocolFrame::HelloAck(ack) => ack,
    ProtocolFrame::Reject(reject) => {
        eprintln!("rejected ({}): {}", reject.code.code(), reject.message);
        return; // fail closed
    }
    _ => return,
};
```

Read `ack.granted`; it is the **exact** set you may use. Do not assume a capability because you
requested it. `ack.limits` are tightened limits (never larger than you requested) and
`ack.body_window_bytes`/`ack.max_in_flight_requests` tell you the backpressure bounds.

### 3.2 Request lifecycle

```
OPEN_REQUEST(request_id, deadline_ms, head)   host -> module
REQUEST_BODY_CHUNK(request_id, bytes)*        host -> module
REQUEST_END(request_id, trailers)             host -> module
  ... module may issue HOST_CALL(...) and read HOST_CALL_RESULT / ERROR ...
RESPONSE_HEAD(request_id, status, headers, body_mode)  module -> host
RESPONSE_BODY_CHUNK(request_id, bytes)*                module -> host
RESPONSE_END(request_id, trailers)                     module -> host
```

Code shape (abridged from the example):

```rust
ProtocolFrame::OpenRequest(open) => body.clear(),
ProtocolFrame::RequestBodyChunk(chunk) => body.extend_from_slice(&chunk.chunk),
ProtocolFrame::RequestEnd(end) => {
    let id = end.request_id;
    let host_time = host_call_now(/* ... */);   // capability-gated
    host_call_log(/* ... */);                    // capability-gated
    write_response_head(id, 200, headers);
    write_response_chunk(id, body.clone());
    write_response_end(id, BridgeHeaders::default());
}
```

Rules that matter in practice: a request starts with exactly one `OPEN_REQUEST`; body ends with
`REQUEST_END` even when empty; response frames for a request stay ordered; `HOST_CALL_RESULT` must
arrive before `RESPONSE_END`; request ids are never reused. The host may interleave other requests
on the connection, but frames for one request are ordered.

### 3.3 Capability-gated host calls

```rust
let call = ProtocolFrame::HostCall(HostCallFrame {
    request_id,
    call: HostCall::Now,
});
write_frame(&mut output, &call, &limits)?;
match read_frame(&mut input, &limits)? {
    ProtocolFrame::HostCallResult(result) => match result.result {
        HostCallResult::Now { unix_nanos } => Some(unix_nanos),
        _ => None,
    },
    ProtocolFrame::Error(error) if error.code == AbiErrorCode::CapabilityDenied => None,
    _ => None,
}
```

A host call is always inside a request id. On denial the host sends a request-scoped `ERROR` with
`CapabilityDenied`; the module should continue the request (log calls are optional) or fail it with
its own `ERROR` if the capability is essential. On a terminal session problem the host sends `ERROR`
with no request id (`fatal = true`); exit cleanly after that.

### 3.4 Host side (test harness shape)

```rust
let mut service = HostService::spawn(
    "author-example",
    ModuleTransportSpec::Stdio {
        program: /* path to author_module */,
        args: vec![],
        env: vec![],
        inherit_env: false,
    },
    21, // generation
    HostServiceConfig {
        handshake: HostHandshakeConfig {
            policy: CapabilityPolicy::with_capabilities([Capability::Log, Capability::Clock]),
            ..Default::default()
        },
        ..Default::default()
    },
)?;
let id = service.open_request(head, 2_000)?;
service.send_request_body(id, b"hello".to_vec())?;
service.end_request(id, BridgeHeaders::default())?;
loop {
    match service.next_event(&mut my_host_calls)? {
        HostEvent::ResponseHead(_) => { /* status and headers */ }
        HostEvent::ResponseBodyChunk(_) => { /* append body */ }
        HostEvent::ResponseEnd(_) => break,
        HostEvent::HostCallCompleted { .. } => { /* optional accounting */ }
        _ => { /* cancellation or error */ }
    }
}
service.stop()?; // fatal close, grace, kill if needed, reap
```

`HostCallHandler` is where the host implements the five host calls behind
`HostCallContext::authorize`; the default `DenyAllHostCalls` is a safe stub.

## 4. In-process (WASM) module: calling convention and skeleton

The Wasmtime runtime is implemented in `caddy_rs_plug::wasm` (feature `wasm-runtime`, on by
default). Guest code receives request `BridgeFrame`s through the convention documented in
[PLUGIN-ABI.md](PLUGIN-ABI.md#in-process-runtime-and-calling-convention):

- exports `memory`, `alloc(len: u32) -> u32`, `handle_request(ptr: u32, len: u32) -> i64`;
- may import `caddy.host_call(call_ptr, call_len, out_ptr, out_len) -> i64`;
- returns `(response_ptr << 32) | response_len` on success, or `-(AbiErrorCode)` on failure.

A minimal guest can be written directly in WAT (this is what `crates/plug/tests/wasm.rs` uses):

```wat
(module
  (import "caddy" "host_call" (func $host_call (param i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 1)
  ;; response frames precomputed into memory by your build/test harness
  (data (i32.const 4096) "\...")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle_request") (param i32 i32) (result i64)
    ;; parse request frames from ptr/len, do work, write response frames
    ;; optional: (drop (call $host_call ...))
    (i64.const 17592186044416))) ;; (4096 << 32) | response_len
```

In a real guest (Rust/C/C++/Zig/...), parse the request frames with the same encoding as the ABI,
write `RESPONSE_HEAD`/chunks/`RESPONSE_END` into a buffer you return, and implement `alloc` with
your language's allocator. The host enforces fuel, epoch timeout, memory and body limits and
validates every response frame; traps and limit failures become typed `WasmError`s and never take
down the host. This build does not link WASI and does not accept the component model (see the
boundaries table in [PLUGIN-ABI.md](PLUGIN-ABI.md#implementation-boundaries)). Author
responsibilities are identical to the external path.

## 5. Capability reference

Deny-by-default: `CapabilityPolicy` starts empty; the operator opts in. The `HELLO_ACK`/
`HostCallContext` grant set is authoritative, and every host call is re-authorized per request
(generation, capability, argument limits, budget).

| Capability | Code | Gates host call(s) | What the host guarantees | What it never grants |
|---|---|---|---|---|
| `log` | 1 | `log` (1) | Structured log record emitted through host logging (message + fields, bounded; secrets are your responsibility) | Filesystem logs, arbitrary sinks, credentials |
| `clock` | 2 | `now` (2) | Wall-clock nanoseconds since the Unix epoch, read from the host clock | Sleep/timer authority, monotonic scheduling guarantees, changing the clock |
| `random` | 3 | `random` (3) | Cryptographically secure random bytes from the host (bounded length) | Seed/entropy inspection, deterministic RNG, key storage |
| `http_client` | 4 | `http_request` (4) | Host-mediated outbound HTTP(S) through host policy/limits; generation-scoped; response buffered in ABI v1 | Raw sockets, unrestricted destinations, TLS private keys, redirect/credential injection |
| `config_read` | 5 | `read_config` (5) | Read-only values from the immutable current-generation config snapshot | Config mutation/reload, filesystem access, other generations' config |

Host-call summary:

| Host call | Code | Required capability | Request limits (defaults) | Failure code |
|---|---|---|---|---|
| `log` | 1 | `log` | message ≤ 4 KiB, ≤ 32 fields, field name/value ≤ 64 B/1 KiB | `InvalidRequest` (invalid), `LimitExceeded` |
| `now` | 2 | `clock` | none | `CapabilityDenied` if not granted |
| `random` | 3 | `random` | ≤ 64 bytes per call | `LimitExceeded`/`InvalidRequest` |
| `http_request` | 4 | `http_client` | URL ≤ 8 KiB, body ≤ 1 MiB, header limits | `HostFailure`, `InvalidRequest`, `LimitExceeded` |
| `read_config` | 5 | `config_read` | key ≤ 256 B, value ≤ 64 KiB | `InvalidRequest`, `CapabilityDenied` |

## 6. Limits and backpressure

Modules must not assume unlimited memory, body size or request concurrency. The host knows the
effective limits and enforces them; a module that exceeds them receives a typed error/cancellation,
never a silent truncation.

| Bound | Default (ABI v1) | Consequence |
|---|---|---|
| Frame payload | 1 MiB | Oversized frame is a protocol error; session closes |
| Body chunk | 64 KiB | Larger chunk is `LimitExceeded` |
| Request/response body | 64 MiB each (hard cap) | Overshoot fails the request with `LimitExceeded` |
| Headers | 128 headers; name 256 B; value 8 KiB | Rejected as `InvalidRequest`/`LimitExceeded` |
| Host calls per request | 1,000 (hard cap 100,000) | Further calls fail with `LimitExceeded` |
| Memory (plugin) | 64 MiB default; 512 MiB hard cap | Host-enforced (WASM path) / operator process limit (external) |
| In-flight requests | host-advertised `max_in_flight_requests` | Host applies backpressure; do not exceed |
| Body window | host-advertised `body_window_bytes` (default 1 MiB) | Do not buffer unacknowledged body beyond the window; the host/transport applies backpressure |

External modules: read at your own pace and let the OS pipe/socket backpressure the host; never
spawn unbounded background queues. If you cannot make progress, fail the request with a typed error
rather than growing memory without bound. Response streaming is expected for large bodies.

## 7. Error handling

Use the stable `AbiErrorCode` values (never invent numbers). In the external protocol, abnormal ends
are `ERROR` frames (request-scoped or fatal) or `REJECT` during the handshake; in-process, the ABI
maps the same codes.

| Code | Name | Return it when |
|---|---|---|
| 1000 | `capability_denied` | A required capability was not granted; a host call is outside the grant |
| 1001 | `stale_generation` | The request belongs to an old configuration generation (host call rejected after reload) |
| 1002 | `limit_exceeded` | Body/header/frame/host-call budget/window exceeded |
| 1003 | `invalid_request` | Malformed frame/payload, invalid method/status/URI/header, invalid state, zero request id |
| 1004 | `host_failure` | The host failed to complete a host call or a host-side operation |
| 1005 | `cancelled` | Client/host cancelled the request or the deadline expired |
| 1006 | `unsupported` | Version/capability/tag/feature the peer does not implement |
| 1007 | `plugin_failed` | Module crash/trap/panic or ABI violation observed by the host |

Guidance: malformed peer input is `invalid_request`; don't panic to signal it. Fail the smallest
scope possible (one request) and keep the connection alive unless the stream is desynchronised, in
which case send a fatal `ERROR` and close. Never expose secrets in error messages: they are
diagnostics, not an authenticated channel.

## 8. Version negotiation

Two versions are negotiated independently and use the same rules:

- **Protocol/ABI major must match exactly**; the host's minor must be ≥ the module's target minor.
  A module compiled for a newer minor than the host is rejected (`unsupported`); a host with a newer
  minor accepts an older module and both sides use the module's target version.
- Zero major versions are invalid.
- The plugin ABI version lives in the descriptor (`abi`); the external transport additionally
  negotiates `protocol`. Both appear in `HELLO_ACK`.
- A minor release may add tags/optional fields/capability codes/error codes; it never renumbers or
  changes existing meanings. Unknown tags/codes are rejected loudly, never skipped.
- A major release is incompatible: upgrade the module or host. Do not attempt cross-major fallback.

## 9. Compatibility contract (what you may rely on)

**Stable across ABI/protocol minor versions (v1.x):**

- Frame layout: `tag:u8 | len:u32 little-endian | payload`; reserved external tags 0x10–0x2C,
  in-process tags 1–9; request ids are non-zero `u64`s assigned by the host.
- Payload encodings: little-endian fixed-width integers, `u32`-length-prefixed UTF-8 strings/bytes;
  bounds-checked decoding with typed errors.
- All existing `BridgeFrame`/`ProtocolFrame` payload layouts and `AbiErrorCode`/capability/host-call
  **values** (1–5, 1–5, 1000–1007); `AbiVersion` negotiation rules.
- Descriptor semantics: name, ABI version, raw capability codes, limits; deny-by-default policy;
  ACK grants a subset of requests and may tighten limits.
- Request lifecycle/cancellation/deadline/backpressure rules in
  [PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md).

**May change in a minor release (additive only):** new optional frame tags/fields, new capability
codes, new error codes, new host calls. A module must ignore frames/codes it does not know only
where the contract says they are additive; unknown tags are errors, so keep your decoder versioned
and fail loudly on unsupported features rather than guessing.

**Breaks on a major release:** tag numbers, payload layouts, version rules, capability/error code
meanings, handshake shape, lifecycle semantics. Support both majors side-by-side rather than
auto-negotiating across majors.

## 10. Testing checklist

- [ ] Handshake succeeds with an allowed policy; `HELLO_ACK.granted` is a subset of requested caps.
- [ ] Handshake is rejected cleanly when a requested capability is denied (module exits, no retry loop).
- [ ] One request round-trips (head, streamed body, trailers, response head/chunks/end).
- [ ] Every host call you use is exercised for granted, denied and host-failure outcomes.
- [ ] Body/header/frame limits and the body window are respected; oversized input produces typed errors.
- [ ] Cancellation (`CANCEL`) and deadline expiry stop work promptly; the request id is not reused.
- [ ] Malformed/truncated/unknown frames and wrong request ids produce typed errors, never panics.
- [ ] Version mismatch (major and newer minor) is rejected with `unsupported`.
- [ ] Crash/EOF mid-request fails only that session, leaves no zombie process, and does not stop the host.
- [ ] Restart policy (if used) has bounded attempts and backoff; no silent restart loop by default.
- [ ] Response headers/status/body are validated as untrusted data by the host; no secrets in logs/errors.

Run `cargo test --offline --locked -p caddy-rs-plug` for the reference contracts and see
`crates/plug/tests/authoring.rs` for a host-driven example test.

## 11. Security responsibilities of module authors

- **Trust nothing from the peer.** Request method/scheme/authority/path/headers/body/trailers, host
  responses/config values and error messages are untrusted data. Validate before using; never pass
  them to shells, `eval`, SQL, template engines or filesystem paths without proper defense.
- **Do not exfiltrate secrets.** Never put credentials, tokens, TLS private keys, cookies or
  internal paths into logs, errors, metric labels or outbound requests. Capabilities are not a
  licence to collect data.
- **Do not attempt ambient access.** No direct filesystem, network, process spawning or environment
  reads are part of either contract; only capability-gated host calls give access. An external
  module may technically call the OS, but that is outside the trust model and the operator's
  isolation is expected to prevent it — do not design around that.
- **Respect isolation and limits.** Use the advertised limits/windows, bound memory/queues, handle
  cancellation/deadlines, and fail closed on protocol violations.
- **Report minimally.** Diagnostics should be actionable without leaking secrets; prefer stable
  `AbiErrorCode` values plus a short message.
- **Keep the descriptor honest.** Request only capabilities you use, declare realistic limits, and
  use a stable name/version so operators can reason about upgrades.
- **Assume least privilege, not persisted trust.** Every request is re-authorized; a grant can be
  removed on reload, and old-generation calls fail with `stale_generation`.

## 12. Runtime performance and pathological behaviour

- Guest startup is cheap once the module is compiled, but compilation is expensive (~6 ms for a
  tiny WAT guest): keep modules small, avoid large data segments, and never compile per request
  (the host compiles once per generation and keeps the `WasmRuntime`).
- Keep `alloc` cheap and deterministic; the host writes the request frames at the returned pointer
  and reads the response at the packed `ptr << 32 | len`. Never return a declared length larger than
  the bytes you actually wrote — the host rejects it before reading (it never trusts the length to
  allocate).
- Do not rely on linear memory being zeroed between requests: a long-lived instance keeps its
  memory and globals. Treat memory and globals as scratch state.
- Every request has a fuel budget, a wall-clock timeout and a host-call budget. Loops or unbounded
  `memory.grow` are stopped (`memory.grow` returns -1 once the `StoreLimits` cap is hit); infinite
  host-call loops are stopped by the budget; trapping (`unreachable`) returns a typed `wasm trap`
  error to the host and a fresh instance is created.
- Host calls are synchronous trusted host code; do not design a plugin that needs to be interrupted
  inside a host call. Split long work into guest-side steps so fuel/epoch can stop it.
- The external-process path pays a ~6 ms spawn/handshake once per generation and ~25–47 us per frame
  round-trip: keep the process alive across requests and avoid oversized or deeply nested frames.

## 13. Where to go next

- [PLUGINS.md](PLUGINS.md) — overview of the two module shapes, host guarantees and limits.
- [PLUGIN-ABI.md](PLUGIN-ABI.md) — in-process WebAssembly host ABI contract.
- [PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md) — external module protocol contract, including the host
  lifecycle section.
- [`crates/plug/src/bin/author_module.rs`](../crates/plug/src/bin/author_module.rs) — the runnable
  example.
- [`crates/plug/tests/authoring.rs`](../crates/plug/tests/authoring.rs) — the documented host-driven
  test and the docs-vs-code consistency checks for capabilities, host calls and error codes.
