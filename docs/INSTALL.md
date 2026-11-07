# Installation

caddy-rs builds from source with Cargo. This page covers the requirements, the build, offline
builds, a first run, and where the server keeps its state.

## Requirements

| Requirement | Notes |
|---|---|
| Rust toolchain | The version pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) (1.98.1). With rustup installed, `cargo` selects it automatically inside the checkout. |
| Operating system | Linux or macOS. |
| Crate source | crates.io for the first build, or a primed local Cargo cache for [offline builds](#offline-builds). |
| External services | None. Building and serving a local configuration need no database, container runtime or other service. |

The workspace uses Rust edition 2021 and declares `rust-version = "1.85"`.

## Build from source

```sh
git clone https://github.com/ben-efros/caddy-rs
cd caddy-rs
cargo build --release
```

The binary is written to `target/release/caddy-rs`. Check it:

```sh
./target/release/caddy-rs version
```

```text
caddy-rs 0.1.0 (Caddy configuration baseline v2.11.9)
```

Run the test suite to verify the build:

```sh
cargo test --workspace
```

CI runs `cargo fmt --all --check`, `cargo test --workspace` and `cargo build --workspace --release`.

## Offline builds

To build without network access, keep a Cargo cache inside the checkout and fill it once while
online:

```sh
export CARGO_HOME="$PWD/.cargo-home"
cargo fetch --locked
```

`cargo fetch` downloads exactly the versions recorded in `Cargo.lock`; `--locked` refuses to
resolve anything else. Add `--offline` to later build and test commands so Cargo reads only that
cache:

```sh
cargo build --release --offline
cargo test --offline --workspace
```

Re-run `cargo fetch --locked` whenever `Cargo.lock` changes. The cache is a normal directory and can
be deleted at any time.

Setting `CARGO_TARGET_DIR` moves build artifacts out of `target/`; with
`CARGO_TARGET_DIR="$PWD/.build"` the binary is `.build/release/caddy-rs`.

## First run

Create a Caddyfile:

```caddyfile
:8080 {
	respond "hello from caddy-rs"
}
```

Start the server:

```sh
./target/release/caddy-rs run --config ./Caddyfile --adapter caddyfile
```

`run` stays in the foreground. It prints the active generation, the listening addresses and the
admin API address to standard error. The example answers `http://localhost:8080/` with
`hello from caddy-rs`.

The same configuration as JSON, in `caddy.json`:

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":8080"],
          "routes": [
            {
              "handle": [
                { "handler": "static_response", "body": "hello from caddy-rs" }
              ]
            }
          ]
        }
      }
    }
  }
}
```

```sh
./target/release/caddy-rs run --config ./caddy.json --adapter json
```

`--adapter` names the format explicitly. When it is omitted, a file whose name starts with
`Caddyfile` is read as a Caddyfile and every other file is read as JSON.

Stop the server with Ctrl-C for a clean shutdown, or from another terminal:

```sh
./target/release/caddy-rs stop
```

## Verify before running

```sh
./target/release/caddy-rs validate --config ./Caddyfile --adapter caddyfile
```

A valid configuration prints `Valid configuration` and exits 0. An invalid one exits non-zero and
prints a located error:

```text
caddy-rs: error[config.invalid]: cannot adapt `./Caddyfile`: invalid configuration at `Caddyfile line 2`: unterminated quoted string before newline
```

## Where state lives

| State | Default | Override |
|---|---|---|
| Data directory | `.caddy-rs` in the working directory | `storage.root` in a JSON configuration; `--data-dir` or `CADDY_RS_DATA_DIR` on `pki` and `trust` |
| Autosave file | `$XDG_CONFIG_HOME/caddy-rs/autosave.json`, else `$HOME/.config/caddy-rs/autosave.json`, else `./.caddy-rs/autosave.json` | `run --autosave-path` |
| Admin API | `localhost:2019` | `admin <address>` in the Caddyfile or `admin.listen` in JSON; `admin off` disables it |

The data directory holds `pki/authorities/<ca-id>/` (the local certificate authority) and
`certificates/`. After a configuration loads successfully, `run` writes the exact JSON to the
autosave file and prints the path. `run --resume` loads that file instead of `--config`.

## Running as a service

`run` stays in the foreground and writes its log lines to standard error, so systemd or a container
entrypoint can supervise it directly. It adopts systemd socket-activated descriptors (`LISTEN_FDS`)
and shuts down cleanly on the first SIGTERM or SIGINT; a second signal closes connections
immediately.
