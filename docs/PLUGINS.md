# Plugins

caddy-rs supports third-party extensions as **modules**. A module is a request transformer — the
equivalent of a Caddy handler, matcher or provider — that the host loads, negotiates with, and
invokes. Two module shapes are supported, and both use the same descriptor, capability, limit,
host-call and error-code model:

| | **In-process WebAssembly** | **Out-of-process module** |
|---|---|---|
| Where the code runs | A core WebAssembly module inside a Wasmtime store in the host process | A separate OS process over stdio, or a module reached through an operator-provided Unix socket |
| Contract | [PLUGIN-ABI.md](PLUGIN-ABI.md) | [PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md) |
| Call model | One implicit request at a time through a fixed guest entry point | Multiplexed requests with request ids, handshake, deadlines and cancellation |
| Isolation | WebAssembly sandbox with host-controlled memory, fuel and wall clock | Process/OS isolation configured by the operator; protocol limits enforced by the host |
| Language | Any toolchain that targets core WebAssembly | Any language that can encode the documented frames and read/write a local transport |
| Recovery | A failed instance is discarded; the host process and other modules continue | The child is reaped; restart is explicit and bounded, with no silent restart loop by default |
| Best suited to | Small, CPU-bound transforms that benefit from low latency and the WASM sandbox | Modules that need native libraries or runtimes, independent restarts, or a separate process boundary |

## Choosing a shape

Choose **in-process WebAssembly** when the module is small and CPU-bound, when the tightest
latency matters, and when the WebAssembly sandbox is the isolation boundary you want. The guest
sees only the ABI: linear memory, encoded frames and capability-gated host calls.

Choose an **out-of-process module** when the module needs native dependencies, a different
runtime, or a language without a suitable WebAssembly target; when it must be restarted or
supervised independently; or when the operator wants the isolation boundary to be the operating
system rather than the WebAssembly engine. The process boundary also means the module can be
written in any language that speaks the wire protocol.

Both shapes are configured by an operator. The module's descriptor is untrusted input; it never
grants authority by itself.

## What the host guarantees

### Capabilities are deny-by-default

A module receives no ambient filesystem, network, clock or randomness access. It requests raw
capability codes in its descriptor, and the host grants them only when the operator's
`CapabilityPolicy` allows that exact capability. The five capabilities in ABI v1 are `log`,
`clock`, `random`, `http_client` and `config_read`; each gates a matching host call. Requesting a
capability is a declaration, never an entitlement. Unknown, duplicate, over-limit or ungranted
requests are rejected rather than ignored.

### Resource limits

Limits are enforced per request and per connection; exceeding one fails the affected invocation or
session, not the host process. The defaults and hard caps are:

| Bound | Value |
|---|---|
| Frame payload | 1 MiB |
| Body chunk | 64 KiB |
| Request or response body | 64 MiB each (hard cap) |
| WASM linear memory | 64 MiB default; 512 MiB hard cap |
| Guest fuel | 10,000,000 per request |
| Wall-clock deadline | 5 s per request |
| Host calls per request | 1,000 default; 100,000 hard cap |
| In-flight requests (external protocol) | Host-advertised, 16 by default |
| Body window (external protocol) | Host-advertised, 1 MiB by default |

Fuel is deterministic; the wall-clock deadline is a safety net, not a deterministic execution
bound. The effective limits are negotiated during the handshake and are never larger than the
module requested.

### Isolation and failure containment

A malformed frame, invalid descriptor or limit violation is a typed error; it cannot panic the
host. In-process modules run in a WebAssembly sandbox with no WASI linking, so there is no ambient
filesystem, network or clock access, and no shared memory or raw pointers cross the boundary.
Out-of-process modules rely on the operator's process isolation (a separate user, container,
namespace or seccomp/landlock profile); the protocol itself cannot create or widen that isolation.
In both shapes a crash or protocol failure is contained to the module's session, and the host fails
closed rather than guessing.

### Lifecycle and versioning

Module services and WASM instances are scoped to one configuration generation. A request or host
call observed against a stale generation fails with `stale_generation`; a reload never reuses the
old service. Versions are negotiated before use: the major version must match exactly, the host's
minor version must be at least the module's target minor, and unknown tags or codes are rejected
rather than skipped.

## Implementation boundaries

- This build accepts core WebAssembly modules only. WASI preview 1/2 and the component model are
  outside this build, so guest modules have no ambient filesystem, sockets or clocks.
- ABI v1 host calls are synchronous and buffered. Streaming host-call HTTP is not part of the ABI.
- The `http_client` capability gates outbound HTTP, but the host must inject a provider. The
  default provider returns a typed `host_failure`.
- Caddy's Go plugin ABI, arbitrary native Caddy plugins and a manifest file format are out of
  scope.

## Documentation

| Document | Contents |
|---|---|
| [PLUGIN-ABI.md](PLUGIN-ABI.md) | Normative in-process WebAssembly host ABI: version negotiation, descriptors, capabilities, host calls, HTTP bridging, the guest calling convention and runtime limits. |
| [PLUGIN-PROTOCOL.md](PLUGIN-PROTOCOL.md) | Normative external module protocol: transport, frame tags, handshake, request lifecycle, flow control, error mapping, security requirements and host lifecycle. |
| [PLUGIN-DEVELOPMENT.md](PLUGIN-DEVELOPMENT.md) | Task-oriented author guide: choosing a path, the template and worked examples, capability and limit tables, testing checklist and security responsibilities. |

The reference implementation is the `caddy-rs-plug` crate in
[`crates/plug`](../crates/plug). Its `wasm-runtime` feature, enabled by default, provides the
in-process runtime; the `protocol` and `host` modules provide the external protocol and its
reference host lifecycle.
