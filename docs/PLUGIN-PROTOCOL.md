# External module protocol

This document defines version 1.0 of the external module protocol: the wire and lifecycle contract
for modules that run outside the caddy-rs host process. The in-process counterpart is the
[WebAssembly plugin host ABI](PLUGIN-ABI.md). For an overview of both module shapes, see
[PLUGINS.md](PLUGINS.md); module authors should start with the
[author guide](PLUGIN-DEVELOPMENT.md). This document is the normative contract for host
implementations and module SDKs.

Where a paragraph says *MUST*, *MUST NOT*, *SHOULD* or *MAY*, the requirement is part of protocol
v1.0. Examples are illustrative unless stated otherwise. The wire layout is implemented by
`crates/plug/src/protocol.rs`, and the integration tests in `crates/plug/tests/protocol.rs` are the
executable form of this document.

The protocol reuses the in-process ABI: same frame layout, same payload encoders, same
`AbiVersion` negotiation, same capability model, same `AbiErrorCode` values. It adds only what an
out-of-process transport needs — handshake, request multiplexing, deadlines, cancellation and
connection-scoped errors. It does not define a second encoding family and does not change the
in-process ABI.

## Transport

- A protocol connection carries **exactly one module instance**. It MUST NOT be shared between
  instances or generations.
- The transport is local: a **Unix domain socket** (preferred) or a **per-module stdio pair**
  (stdin/stdout of a spawned child process). TCP, UDP, QUIC and any other network transport are out
  of scope; an implementation MUST NOT expose the protocol on a listener reachable from untrusted
  networks.
- If the host spawns the module process, stdin/stdout are the protocol stream and stderr MAY be
  captured as diagnostics. No other file descriptors are inherited or passed; FD passing is
  forbidden.
- The socket path/process and its isolation are configured by the operator (separate user,
  container, namespace, seccomp/landlock profile, socket permissions). The protocol itself cannot
  create or widen isolation.
- Frames are streamed in both directions; a connection MAY carry several in-flight requests
  interleaved, but frames belonging to one request MUST stay ordered relative to each other.
- Closing the transport aborts all in-flight requests. A clean shutdown is: host sends a fatal
  `ErrorFrame` (or the last response end) and then closes the connection; a module must finish or
  abandon work when the transport closes.
- The host MUST apply a connection-establishment timeout, a handshake timeout and an idle timeout
  appropriate to its configuration; timeouts are enforced by closing the transport and failing all
  open requests.

## Framing (normative)

A frame is exactly the in-process ABI frame layout:

```
tag: u8 | payload_len: u32 little-endian | payload: payload_len bytes
```

- No padding and no alignment.
- `payload_len` MUST NOT exceed `AbiLimits::max_frame_payload` (ABI default 1 MiB; the effective
  limit is at most the ABI default and is negotiated in the ACK via limits).
- Integer/string encodings are the ones from [PLUGIN-ABI.md](PLUGIN-ABI.md): little-endian fixed
  width integers, `u32`-length-prefixed UTF-8/byte strings, bounds-checked on decode.
- Unknown tags MUST be rejected (`ProtocolError::Wire(WireError::UnknownFrameTag)`); they are never
  skipped or ignored.
- In-process ABI tags `1..=9` are **reserved for the in-process transport** and MUST be rejected on
  this protocol (`ProtocolError::InProcessFrameTag`). The external protocol uses the reserved tag
  range `0x10..=0x2C`.
- A request-scoped payload starts with a `request_id: u64`; `0` is reserved and is a protocol error
  (`ProtocolError::ZeroRequestId`). Handshake frames are connection-scoped and carry no request id.
- Any malformed frame is a typed error, never a panic. The host MUST treat a malformed frame as a
  fatal connection error (`AbiErrorCode::InvalidRequest`), send a fatal error frame if the
  connection is still writable, and close the transport.

| Tag | Name | Direction | Payload |
|---|---|---|---|
| `0x10` | `HELLO` | module → host | protocol version, descriptor (name, ABI version, requested capability codes, limits) |
| `0x11` | `HELLO_ACK` | host → module | effective protocol version, negotiated ABI versions, granted capabilities, effective limits, `max_in_flight_requests`, `body_window_bytes` |
| `0x12` | `REJECT` | host → module (also module → host for an invalid ACK) | rejection phase, `AbiErrorCode`, message |
| `0x20` | `OPEN_REQUEST` | host → module | request id, `deadline_ms` (`0` = none), bridged request head |
| `0x21` | `REQUEST_BODY_CHUNK` | host → module | request id, bytes (≤ `max_body_chunk`, ABI default 64 KiB) |
| `0x22` | `REQUEST_END` | host → module | request id, request trailers |
| `0x23` | `RESPONSE_HEAD` | module → host | request id, bridged response head |
| `0x24` | `RESPONSE_BODY_CHUNK` | module → host | request id, bytes |
| `0x25` | `RESPONSE_END` | module → host | request id, response trailers |
| `0x26` | `HOST_CALL` | module → host | request id, capability-gated host call |
| `0x27` | `HOST_CALL_RESULT` | host → module | request id, typed host-call result |
| `0x28` | `CANCEL` | either direction | request id, `AbiErrorCode`, message |
| `0x29` | `ERROR` | either direction | request id (`0` = connection), fatal flag, `AbiErrorCode`, message |

The payload types are the in-process ABI types (`RequestHead`, `ResponseHead`, `BridgeHeaders`,
`HostCall`, `HostCallResult`, `AbiErrorFrame` and their `AbiLimits` bounds) encoded with the existing
`encode`/`decode` methods — see `crates/plug/src/bridge.rs` and `crates/plug/src/hostcall.rs`.

## Handshake (normative)

1. The module opens the transport and sends exactly one `HELLO` before any other frame. `HELLO`
   carries the external **protocol version** and the module's **untrusted descriptor** (name, plugin
   ABI version, raw capability codes, requested limits).
2. The host validates, in this order:
   1. negotiate the external protocol version: same `major.minor` rules as the ABI version
      (`negotiate` — identical major, host minor ≥ module minor); a zero major is invalid;
   2. validate the descriptor structurally (`PluginDescriptor::validate`);
   3. validate and grant capabilities against the operator `CapabilityPolicy` (deny-all by default)
      — unknown capability codes are rejected, duplicates are rejected, ungranted capabilities are
      rejected (`CapabilityDenied`);
   4. negotiate the plugin ABI version against the host's implemented ABI (same rules);
   5. tighten the module's requested limits element-wise to the host's limits;
   6. choose positive `max_in_flight_requests` and `body_window_bytes`.
3. On success the host MUST reply with one `HELLO_ACK` carrying the effective protocol version (the
   module's target version), both ABI versions, the exact granted capability set, the effective
   limits and the two window bounds. A host MUST NOT grant a capability that the module did not
   request and MUST NOT advertise limits above the module's requested limits.
4. On failure the host MUST reply with `REJECT` (phase and stable error code) and close the
   connection. The module MUST NOT send further frames after the rejection.
5. The module validates the `HELLO_ACK` before using the session: protocol version equal to what it
   requested, ABI versions compatible, grants a subset of what it requested, limits not larger than
   requested, positive window bounds. An invalid ACK is a protocol violation: the module sends
   `REJECT` (phase `Other`, code `InvalidRequest`) and closes.
6. A connection carries at most one handshake. Re-handshaking, sending a second `HELLO`, or sending
   non-handshake frames before the ACK are handshake/state violations and MUST fail the connection.
7. The handshake binds the connection to the validated descriptor and the host's configuration
   generation. Later frames cannot change the plugin name, ABI version, capabilities or limits.

Example (illustrative, hex): `HELLO` for name `echo`, ABI 1.0, one requested capability (log),
default limits, has tag `0x10`, payload length 41, then version `01 00 00 00`, name length
`04 00 00 00` + `echo`, ABI `01 00 00 00`, capability count `01`, code `01 00 00 00`, then the four
limit fields (u64/u64/u32/u64, little-endian).

## Versions and compatibility

Two independent versions are negotiated:

| Version | Where | Rules |
|---|---|---|
| External protocol version | `HELLO.protocol` / `HELLO_ACK.protocol` | `AbiVersion` rules: major must match exactly, host minor ≥ module minor, zero major invalid; the effective version is the module's target version. |
| Plugin ABI version | `HELLO.descriptor.abi` / `HELLO_ACK.abi` | Same rules; the host must implement the plugin's ABI major and a minor at least as new. |

A new protocol minor version MAY add tags or optional trailing payload fields, but MUST NOT renumber
or change existing tags, payload layouts or stable values. Unknown tags and unknown/undefined
values are rejected rather than skipped, because skipping would let a peer compiled against a newer
minor version run with silently missing behaviour. A protocol major version change is incompatible:
the handshake fails with `Unsupported` and the peer must be upgraded. Capability codes and
`AbiErrorCode` values are stable and may only be appended in a minor version.

## Capabilities and authorization (normative)

Capabilities are the same five ABI v1 capabilities (`log`, `clock`, `random`, `http_client`,
`config_read`). The module requests raw codes in its descriptor; the operator policy is deny-all by
default; the ACK carries exactly the requested ∩ granted set.

- The host MUST authorize **every** `HOST_CALL` against the granted set, the current configuration
  generation and the per-request budget. A call outside the grant MUST fail with
  `AbiErrorCode::CapabilityDenied`; a stale generation with `StaleGeneration`; over-budget or
  oversized calls with `LimitExceeded`/`InvalidRequest`.
- The module MUST NOT assume a capability is granted because it requested it, and MUST handle a
  denied/failed host call.
- The host MUST NOT use a capability as an implicit trust signal: granted capabilities widen the
  host-call surface only, never filesystem/network/secret access.

## Request lifecycle (normative)

- Request ids are assigned by the host, MUST be non-zero and unique for the connection's lifetime,
  and MUST never be reused after a request ends (including cancellation).
- A request starts with exactly one `OPEN_REQUEST` carrying the request head and `deadline_ms`
  (remaining milliseconds; `0` means no deadline). The host MUST set a positive deadline when its
  configuration imposes one.
- Request bodies: `REQUEST_BODY_CHUNK` frames and a final `REQUEST_END` with trailers (possibly
  empty). Body mode comes from the head (`Empty`, `Buffered { length }`, `Streamed`). Empty body
  still sends `REQUEST_END`.
- Response: the module sends exactly one `RESPONSE_HEAD`, then zero or more
  `RESPONSE_BODY_CHUNK`, then `RESPONSE_END` with trailers. The response head's declared body mode
  must match what follows.
- `HOST_CALL`/`HOST_CALL_RESULT` frames for a request may be interleaved with that request's frames;
  the result belongs to the same request id and must appear before the response end. The host MUST
  answer every host call exactly once (result or an error frame).
- At most `max_in_flight_requests` requests may be open at once. The host MUST NOT exceed the bound
  and MUST apply backpressure to the client until a request finishes.
- Cancellation: either side MAY send `CANCEL` for a request with a stable code (`Cancelled`,
  `LimitExceeded`, `PluginFailed`, `InvalidRequest`). After `CANCEL`, the sender MUST NOT send more
  non-error frames for that request; the receiver SHOULD stop work and MAY reply with a request-
  scoped `ERROR` (typically `Cancelled`) before forgetting the id. Ids of cancelled requests are
  never reused.
- Deadlines: the host SHOULD convert its request deadline to `deadline_ms` and MUST enforce it by
  sending `CANCEL` (`Cancelled`) and failing the HTTP request when it expires. A module SHOULD honour
  the deadline but the host never relies on module cooperation for enforcement.
- An `ERROR` frame with `fatal = false` fails one request and is followed by no more frames for that
  request; with `fatal = true` it terminates the connection and all open requests. Error frames are
  terminal for their scope.

## Flow control, budgets and backpressure (normative)

The protocol does not add credit frames; flow control is expressed with the negotiated bounds and
the existing in-process accounting types (`AbiLimits`, `BodyBudget`):

- Both sides MUST enforce per-frame (≤ 1 MiB), per-chunk (≤ 64 KiB), header/trailer (count/name/
  value), URI and error-message limits; violations are `AbiErrorCode::LimitExceeded`.
- Response bodies are additionally bounded by `limits.max_response_body_bytes`; request bodies by
  `limits.max_request_body_bytes` and by the host's client-side body limit. Overshoot MUST cancel
  the request and fail it with `LimitExceeded`; it is never truncated silently.
- `body_window_bytes` bounds unacknowledged inbound body bytes per request. A sender MUST NOT have
  more than the window outstanding before the receiver has consumed earlier chunks; if it would,
  it MUST wait (apply transport-level backpressure) rather than buffer without bound. A receiver
  that cannot make progress MUST cancel the request instead of growing memory without limit.
- The host MUST stop reading from the client when the module is the bottleneck (bounded queues,
  not unbounded buffering) and MUST close the connection when a peer stops consuming beyond the
  idle timeout.
- The per-request host-call budget (`max_host_calls_per_request`) is enforced by the host call
  context; exceeding it fails the call and, if the module continues, cancels the request.

## Error handling and `AbiErrorCode` mapping (normative)

Every abnormal end carries a stable `AbiErrorCode` (values 1000–1007 from the in-process ABI):

| Protocol condition | Code |
|---|---|
| Malformed frame/payload, trailing bytes, zero request id, invalid state | `InvalidRequest` (1003) |
| Unknown tag, unknown capability code, unsupported protocol/ABI major or newer minor | `Unsupported` (1006) |
| Capability not granted by policy, or host call outside the granted set | `CapabilityDenied` (1000) |
| Frame/chunk/header/body/host-call/window limit exceeded | `LimitExceeded` (1002) |
| Request belongs to a stale configuration generation | `StaleGeneration` (1001) |
| Peer cancelled the request, deadline expired | `Cancelled` (1005) |
| Module trapped/panicked/violated the ABI in a way the host observes | `PluginFailed` (1007) |
| Host-side failure performing a host call or closing the transport | `HostFailure` (1004) |

The `REJECT` frame carries the phase (`ProtocolVersion`, `AbiVersion`, `Descriptor`, `Capability`,
`Other`) plus the code. `ERROR` frames carry the code, a `fatal` flag and a diagnostic message
(capped at 1 KiB). Error-code values may be appended in a minor version but never renumbered.

## Security model (normative MUSTs)

The host MUST assume the module, the descriptor, every frame and every field are attacker-controlled
until validated:

- Validate the protocol version, descriptor structure, ABI version, capability codes and limits
  before loading/attaching the module; reject rather than clamp or ignore.
- Never trust module-provided limits: enforce the effective limits and hard caps host-side; never
  allocate based on an unvalidated length.
- Never trust module-provided data as authority: HTTP response status/headers/trailers are data,
  not privilege; the host validates/normalizes them like any other response and strips hop-by-hop
  headers.
- Authorize every host call against the granted set and generation; do not cache a previous
  decision across generations.
- Do not pass secrets, TLS private keys, file descriptors, environment secrets or raw sockets over
  the protocol. Only data requested through capability-gated host calls crosses the boundary.
- Enforce isolation outside the protocol: separate process/user/container/namespace, scrubbed
  environment, no ambient filesystem or network access, restrictive socket permissions or
  inherited stdio only; the operator configures this and the host must fail closed if it cannot.
- Enforce handshake/request/idle timeouts, in-flight and body bounds, and close the connection after
  a fatal error; a misbehaving peer must not be able to stall or exhaust the host.
- One module instance per connection and per configuration generation; on reload the host MUST NOT
  reuse the old connection/generation and MUST fail calls with `StaleGeneration`.
- Log/audit handshake decisions (granted capabilities, rejected codes) and abnormal ends.

## Relationship to the in-process ABI

- **In-process ABI** ([PLUGIN-ABI.md](PLUGIN-ABI.md)): the host embeds a WASM engine in the same
  process and calls the module through the ABI; `BridgeFrame` is the whole wire format, one implicit
  request at a time, no handshake frames.
- **External module protocol** (this document): the module runs in another process; the same bridge
  payload encoders and types are wrapped in a `request_id` envelope with a handshake, deadlines and
  cancellation. It does not require WASM: a module can be implemented in any language that speaks
  the wire protocol. No WASM-engine assumptions (fuel, linear memory) are part of this protocol;
  those belong to the in-process runtime.
- A host runtime can share one transport-agnostic "module session" abstraction: drive a WASM
  instance in-process with `BridgeFrame`s, or a process over this protocol, with the same capability
  and limit model. The reference types live in `caddy_rs_plug::protocol` so both paths use one
  implementation.

## Host lifecycle (normative for host implementations)

The reference host implementation is `caddy_rs_plug::host`. It fulfils the protocol rules above for
an out-of-process module service and integrates with the configuration-generation lifecycle
(`caddy_rs_core::GenerationResource`/`GenerationResources`), so a module service is generation-scoped
exactly like listeners and other runtime resources. Host implementations MUST behave as follows.

### State machine

```
spawn/connect ──► HELLO received ──► HELLO_ACK sent ──► Running
                     │                                   │
                     └─ validation failed ──► REJECT sent ──► Reaping
Running ── crash/EOF/malformed frame ──► Failed (in-flight requests failed) ──► Reaping
Running ── generation stop/fatal close ──► Stopping ──► Reaping ──► Stopped
```

- **Provisioning:** spawn the process (scrubbed environment, piped stdio) or connect the
  operator-configured Unix socket, then perform the host side of the handshake. A rejected
  handshake MUST send `REJECT` when the transport is still writable, then terminate and reap the
  process; it MUST NOT leave a half-handshaken service attached to a generation.
- **Running:** only after `HELLO_ACK` has been written may the host send request frames.
- **Stopping:** the host MUST send a connection-fatal `ERROR` frame (normative code `Cancelled`,
  message identifying the generation stop), close the write side, wait up to the operator grace
  period for the process to exit, then kill and `wait` for it. Reaping is mandatory: a stopped
  generation MUST leave no zombie or orphan process. The operation MUST be idempotent because the
  lifecycle framework may call `stop` then `cleanup`.
- **Failed:** a crash, EOF, I/O error, malformed/oversized frame or protocol-state violation
  transitions the service to Failed. The host MUST fail every in-flight request with a typed error
  (at least `PluginFailed`; cause-specific codes where applicable) and MUST reap the child. A failed
  service cannot be reused: a new generation means a new process/connection.
- **Reaping:** the host owns the child process. It MUST `wait` for it (graceful or after kill) before
  considering the service stopped; a generation that is dropped must still reap in its destructor.

### Generation scoping and integration

- A service belongs to exactly one configuration generation; its handshake and all requests use
  that generation's policy, limits and granted capabilities. It MUST NOT be reused across
  generations.
- The host runtime SHOULD create the service while provisioning the generation
  (`GenerationHooks::provision`), attach it through `GenerationResources::attach` (wrapped as a
  `GenerationResource`), let `start` mark it active, and use `stop`/`cleanup` to send the fatal close
  and reap. Reloading/retiring the generation therefore stops the service with the generation, and
  a failed provisioning/start rolls back attached services through the framework's exactly-once
  cleanup.
- A request or host call observed after the owning generation is no longer active MUST fail with
  `StaleGeneration`; the host MUST NOT route it to the new generation's service.
- On shutdown order: the generation's stop hook runs before the process is drained/cleaned; the host
  should stop accepting new requests for that service immediately, then fail or finish in-flight
  requests according to the configured drain/grace policy.

### Crash isolation and supervision

- A module crash MUST NOT abort, panic or take down the host process: it is a typed error on the
  session, all in-flight requests are failed, the child is reaped, and other services/generations
  continue to operate.
- `RestartPolicy::Never` is the **default**: a crashed service is reported (for example
  `CrashIsolated { code }`) and stays stopped; there is no silent restart loop. Operators may opt in
  to `OnFailure { max_restarts, backoff }`; the host MUST apply the backoff, re-run the full
  handshake on the new process/connection, count attempts, and report `RestartExhausted` when the
  bound is reached. A restart is a new process/connection, never a reuse of the failed one.
- A crash while a request is in flight fails only that request/session; the host process and other
  modules MUST remain healthy. Malformed/oversized frames are treated like a crash for the session
  (`InvalidRequest`) and close the connection rather than attempting to resynchronise the stream.
- Restarts MUST be generation-scoped: a restart never crosses a configuration reload; after a reload
  the old generation's supervisor is stopped and the new generation creates its own service.

### Host calls

- The host MUST authorize every `HOST_CALL` against the owning generation, the exact granted
  capability set, argument limits and the per-request budget before invoking an implementation. A
  denied call MUST be answered with a request-scoped `ERROR` frame carrying `CapabilityDenied`
  (or the appropriate code); a host implementation error uses `HostFailure`/`InvalidRequest`.
  `HOST_CALL_RESULT` MUST answer the same request id before `RESPONSE_END`.
- The host provides the in-process ABI's five host-call implementations (`log`, `now`, `random`,
  `http_request`, `read_config`) through the operator policy; external modules get no other ambient
  authority.
- A host call received for an unknown/finished request, or after a fatal error, is a protocol
  violation (`InvalidRequest`) and fails the session.

### Clarifications for v1.0

- Request ids are host-assigned and unique per connection; the codec rejects `0` and the host MUST
  not reuse an id after response end/cancellation. The protocol has no retransmission: any transport
  failure is terminal for the session (requests fail; the connection is not resumed).
- `deadline_ms = 0` means "no deadline"; the host still enforces its own request timeout and, on
  expiry, sends `CANCEL` (`Cancelled`) and fails the HTTP request. `CANCEL` has no acknowledgement;
  the receiver stops work and the id is retired.
- Only one handshake per connection; `HELLO`/`HELLO_ACK`/`REJECT` are never valid after it. The
  connection is closed after a fatal `ERROR` or `REJECT`.
- A clean close is a connection-fatal `ERROR` frame followed by transport close. EOF without that
  frame is an abnormal end (`PluginFailed`) even if the process exit status is 0.

## Normative vs illustrative summary

| Area | Normative |
|---|---|
| Frame layout, tags, payload layouts, limits | Yes — `crates/plug/src/protocol.rs` is the source of truth; the tables above explain it. |
| Handshake sequence, validation order, version rules, grant rules | Yes. |
| Request lifecycle, cancellation/deadline/error/state rules | Yes. |
| Backpressure windows and budget rules | Yes (bounds), implementation mechanics (queues/scheduling) are host-defined. |
| Hex examples, transport choice details, audit log formats | Illustrative/host-defined. |

## Evidence

`cargo test --offline --locked -p caddy-rs-plug` runs the crate suite; `crates/plug/tests/protocol.rs`
contains golden frame layouts, handshake accept/reject cases (version mismatch, ungranted/unknown
capabilities, invalid ACKs, malformed frames, oversized payloads, unknown and in-process tags, zero
request ids), the in-process external-module echo driver, cancellation, and malformed-input checks
that must produce typed errors and never panics. `crates/plug/tests/host.rs` exercises the reference
host lifecycle against real child processes over stdio.
