# Installation

caddy-rs builds from source with Cargo. This page covers the requirements, the build, offline
builds, the proxy-manager sidecar, a first run, and where the server keeps its state. The full
command reference is in [CLI.md](CLI.md).

## Requirements

| Requirement | Notes |
|---|---|
| Rust toolchain | The version pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) (1.98.1). With rustup installed, `cargo` selects it automatically inside the checkout. |
| Operating system | Linux or macOS. |
| Crate source | crates.io for the first build, or a primed local Cargo cache for [offline builds](#offline-builds). |
| External services | None. Building and serving a local configuration need no database, container runtime or other service. |

The workspace crates use Rust edition 2021 and declare `rust-version = "1.88"`; a dependency
(`jsonwebtoken` 10.3) itself requires 1.88. The nested `pm/` workspace also uses edition 2021 but
declares `rust-version = "1.85"`. The pinned 1.98.1 toolchain satisfies both. The optional
`wasm-runtime` feature of the plug crate pulls in `wasmtime`; build it with the pinned toolchain.

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
caddy-rs 0.1.0-trial.6 (Caddy configuration baseline v2.11.9)
```

Run the test suite to verify the build:

```sh
cargo test --workspace
```

The CI workflow runs `cargo fmt --all --check`, `cargo test --workspace` and
`cargo build --workspace --release`.

## Offline builds

To build without network access, keep a Cargo cache inside the checkout and fill it once while
online:

```sh
export CARGO_HOME="$PWD/.cargo-home"
cargo fetch --locked
```

`cargo fetch` downloads exactly the versions recorded in `Cargo.lock`; `--locked` refuses to
resolve anything else. Keep `CARGO_HOME` exported and add `--offline` to later build and test
commands so Cargo reads only that cache:

```sh
cargo build --release --offline
cargo test --offline --workspace
```

Re-run `cargo fetch --locked` whenever `Cargo.lock` changes. The cache is a normal directory and can
be deleted at any time.

The proxy manager is a nested workspace with its own `pm/Cargo.lock`, so an offline build of it
needs its own fetch, with the same `CARGO_HOME`:

```sh
(cd pm && cargo fetch --locked)
```

Setting `CARGO_TARGET_DIR` moves build artifacts out of `target/`; with
`CARGO_TARGET_DIR="$PWD/.build"` the binary is `.build/release/caddy-rs`.

## Proxy manager sidecar

`caddy-rs-pm` is the proxy-manager daemon. It is a separate nested workspace (`pm/`) with its own
lockfile, and it is built from source in the same tree:

```sh
cd pm
cargo build --release
./target/release/caddy-rs-pm version
```

```text
caddy-rs-pm 0.1.0-trial.6 (caddy-rs 0.1.0-trial.6)
```

> **Not yet in the published release archives.** The published `v0.1.0-trial.6` archives contain
> `caddy-rs` only. The program repository's `version.json` records
> `sidecar.packaged_in_release_archives` as "from the next cut after 0.1.0-trial.6; the published
> trial.6 archives contain caddy-rs only". Until then, build `caddy-rs-pm` from source as above.
> Both workspaces are versioned `0.1.0-trial.6`, so a sidecar built from this tree pairs with the
> `caddy-rs` from the same tree.

### Install as a systemd service

`caddy-rs-pm install` writes `/etc/systemd/system/caddy-rs-pm.service`. It must run as root, and the
service account named in the unit (default `caddy-rs:caddy-rs`) and its data directory (default
`/var/lib/caddy-rs`, writable by that account) must already exist — the installer creates neither:

```sh
sudo useradd --system --home /var/lib/caddy-rs --shell /usr/sbin/nologin caddy-rs
sudo install -d -o caddy-rs -g caddy-rs -m 0750 /var/lib/caddy-rs
sudo install -m 0755 caddy-rs /usr/local/bin/caddy-rs
sudo install -m 0755 caddy-rs-pm /usr/local/bin/caddy-rs-pm
sudo caddy-rs-pm install
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-rs-pm
```

`install` defaults:

| Setting | Default | Override |
|---|---|---|
| Unit file | `/etc/systemd/system/caddy-rs-pm.service` | fixed path |
| `ExecStart` binary | absolute path of the `caddy-rs-pm` that ran `install` | `--binary-path`, `PM_BINARY_PATH` |
| Data directory | `/var/lib/caddy-rs` | `--data-dir`, `PM_DATA_DIR` |
| Management API listen address | `127.0.0.1:81` | `--listen`, `PM_LISTEN` |
| caddy-rs admin API URL | `http://127.0.0.1:2019` | `--admin-url`, `PM_ADMIN_URL` |
| Service user/group | `caddy-rs:caddy-rs` | `--user`, `--group`, `PM_USER`, `PM_GROUP` |
| Environment file | `/etc/caddy-rs-pm.env` | fixed path |

The unit's `ExecStart` puts the global options before the `serve` subcommand — the order is
load-bearing, because `serve` rejects global flags after the subcommand:

```text
ExecStart=/usr/local/bin/caddy-rs-pm --data-dir /var/lib/caddy-rs --compat native --log-format json --log-level info serve --listen 127.0.0.1:81 --admin-url http://127.0.0.1:2019 --shutdown-timeout 30
```

An existing unit file is only replaced with `--force`; if the generated content is identical,
`install` says so and exits successfully. `uninstall` removes the unit only when it is byte-identical
to what a stock install would write (pass `--force` otherwise) and removes the environment file.

The environment file is written when a bootstrap password or TOTP value is supplied (whether or not
the email is); it records whichever of the three globals are set. It is root-owned, mode 0600, and
when written the unit references it as `EnvironmentFile=-/etc/caddy-rs-pm.env`: the leading `-`
makes a missing file non-fatal, so a plain install starts without credentials. Installing without
credentials deletes a stale file left by an earlier install. Only the password source
(`PM_BOOTSTRAP_ADMIN_PASSWORD`) is usable today: `serve` creates no administrator unless the email
is also set, and the TOTP bootstrap path fails because it verifies a code before enrolling a secret
(T-AUTH-002). Supply the email and password together; do not rely on
`PM_BOOTSTRAP_ADMIN_TOTP` yet. [pm/README.md](../pm/README.md) describes
the workspace's crate layout; the operator-facing configuration is the unit file and the environment
variables above.

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

`run` stays in the foreground and prints the autosave path, the active generation, the listening
addresses and the admin API address to standard error, for example:

```text
caddy-rs: autosaved config (load with --resume flag) `/home/you/.config/caddy/autosave.json`
caddy-rs: configuration active (generation 1)
caddy-rs: listening on :8080 (bound [::]:8080)
caddy-rs: admin API listening on [::1]:2019
```

The example answers `http://localhost:8080/` with `hello from caddy-rs`.

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

`--adapter` names the format explicitly and always wins. When it is omitted, the file's base name
decides: a name starting with `Caddyfile` is adapted as a Caddyfile, anything else is parsed as JSON.
With no `--config` (and no `--resume`), `run` uses `./Caddyfile` when that file exists.

Stop the server with Ctrl-C for a clean shutdown, or from another terminal:

```sh
./target/release/caddy-rs stop
```

## Verify before running

```sh
./target/release/caddy-rs validate --config ./Caddyfile --adapter caddyfile
```

A valid configuration prints `Valid configuration` and exits 0. An invalid one exits non-zero (1)
and prints a located error:

```text
caddy-rs: error[config.invalid]: cannot adapt `./Caddyfile`: invalid configuration at `Caddyfile line 2`: unterminated quoted string before newline
```

## First-boot authentication (`setup`)

`caddy-rs setup` generates a temporary activation layer and a Caddyfile for first-boot enrolment
(a caddy-rs extension; stock Caddy has no `setup` subcommand):

```sh
./target/release/caddy-rs setup --domain example.com --auth-method webauthn
```

`setup` writes `<data-dir>/setup/Caddyfile` and then runs it in the foreground; do not start a
second `run` on the same file while it is running. To serve the generated file later, use
`./target/release/caddy-rs run --config <data-dir>/setup/Caddyfile --adapter caddyfile` after the
first process exits (the file is not removed).

The generated global block uses `local_certs` and the site listens on `:443` with automatic HTTPS
also binding `:80`, so a first run normally needs root or `CAP_NET_BIND_SERVICE`. For an
unprivileged trial, pass a high `--listen-address` port, but note that only the port is honored:
the listener binds all interfaces (T-SETUP-007).

`--auth-method` is `webauthn` (default) or `totp`. The generated activation route is currently a
placeholder `503` until the proxy-manager enrolment service is wired, so it proves the first-boot
flow but does not yet enrol a credential. Details: [`setup` in CLI.md](CLI.md#setup),
[AUTHN.md](AUTHN.md) (login and token lifecycle), [TOTP.md](TOTP.md) (RFC 6238 details) and
[WEBAUTHN.md](WEBAUTHN.md) (passkey registry and the current `setup` limitation).

## Where state lives

| State | Default | Override |
|---|---|---|
| Data directory | Caddy's `$XDG_DATA_HOME/caddy` or `$HOME/.local/share/caddy`; legacy `.caddy-rs` in the working directory when it already exists | `run --data-dir`; `storage.root` in a JSON configuration; `CADDY_RS_DATA_DIR` |
| Autosave file | `$XDG_CONFIG_HOME/caddy/autosave.json`, else `$HOME/.config/caddy/autosave.json`, else `./caddy/autosave.json`; a legacy `caddy-rs` autosave is used only when the Caddy path is absent | `run --autosave-path` |
| Admin API | `localhost:2019` | `admin <address>` in the Caddyfile or `admin.listen` in JSON; `admin off` disables it |

The data directory holds `pki/authorities/<ca-id>/` (the local certificate authority) and
`certificates/`. Caddy's XDG path is the default so an existing Caddy data directory can be reused
in place; an existing `.caddy-rs` directory is still used for continuity. After a configuration
loads successfully, `run` writes the exact JSON to the autosave file and prints the path. `run
--resume` loads that file instead of `--config`.

## Running as a service

`run` stays in the foreground and writes its log lines to standard error, so systemd or a container
entrypoint can supervise it directly. It adopts systemd socket-activated descriptors (`LISTEN_FDS`)
and shuts down cleanly on the first SIGTERM or SIGINT; a second signal closes connections
immediately. To run `caddy-rs` itself as a service, install it under `/usr/local/bin` and point a
unit's `ExecStart` at `caddy-rs run --config /etc/caddy/Caddyfile --adapter caddyfile`; the proxy
manager's generated unit (above) already expects a `caddy-rs` service on the default admin API.
