# caddy-rs module template

A minimal **out-of-process** caddy-rs module. It is a standalone crate (its own `[workspace]`)
so copying it does not add anything to the caddy-rs workspace build graph.

## Copy this directory to start a module

```sh
cp -r crates/plug/template my-module
cd my-module
```

Then change, in `Cargo.toml`:

1. `package.name` (and `[[bin]] name`) to your module's name;
2. the `caddy-rs-plug` dependency: keep the path dependency for local development, or switch to
   the published version once available (`caddy-rs-plug = "0.1"`).

And in `src/main.rs`:

1. the descriptor `name`, `abi` version, requested `capabilities` and `limits` — request only
   capabilities you use; the operator policy is deny-by-default;
2. the request handler: replace the echo body/status with your logic;
3. host calls: keep `HelloAck.granted` checks and handle `CapabilityDenied` gracefully.

## Build and test

From the caddy-rs repository root:

```sh
# build the template binary (independent workspace; does not touch the main Cargo.lock)
cargo build --offline --locked --manifest-path crates/plug/template/Cargo.toml

# run the reference host integration test (builds + exercises the template end to end)
cargo test --offline --locked -p caddy-rs-plug --test template
```

Or inside a copied module:

```sh
cargo build
cargo test
```

There is no standalone host binary here: the module expects a protocol peer on stdin/stdout. Use a
host that implements the external module protocol (`caddy_rs_plug::host::HostService`), or the
integration test above as a reference harness.

## What this template demonstrates

- `HELLO` with an untrusted descriptor, `HELLO_ACK` grant handling, `REJECT` fail-closed;
- one echo-style request: `OPEN_REQUEST` → body chunks → `REQUEST_END` → response head/chunk/end;
- one capability-gated host call (`log`) with denial handling;
- clean exit on fatal `ERROR` / `CANCEL` (generation stop).

See `docs/PLUGIN-DEVELOPMENT.md` in the caddy-rs repository for the full author guide, capability
table and compatibility contract.
