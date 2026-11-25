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
(`jsonwebtoken` 10.3) itself requires 1.88. The proxy-manager crates (`pm/`) are packages in the
same workspace and inherit that same `rust-version` of 1.88; they previously declared 1.85 in their
own workspace, so building them now needs 1.88. The pinned 1.98.1 toolchain satisfies this. The
optional `wasm-runtime` feature of the plug crate pulls in `wasmtime`; build it with the pinned
toolchain.

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
caddy-rs 0.1.0-trial.7 (Caddy configuration baseline v2.11.9)
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

The proxy manager is a member of the same workspace and shares the root `Cargo.lock`, so a single
`cargo fetch --locked` at the repository root primes an offline build of both binaries. Build the
sidecar by name:

```sh
cargo build --release -p caddy-rs-pm
```

Setting `CARGO_TARGET_DIR` moves build artifacts out of `target/`; with
`CARGO_TARGET_DIR="$PWD/.build"` the binary is `.build/release/caddy-rs`.

## Proxy manager sidecar

`caddy-rs-pm` is the proxy-manager daemon. It is a package in the same workspace, built from source
in the same tree:

```sh
cargo build --release -p caddy-rs-pm-cli
./target/release/caddy-rs-pm version
```

```text
caddy-rs-pm 0.1.0-trial.7 (caddy-rs 0.1.0-trial.7)
```

> **Historical note on the archives.** The published `v0.1.0-trial.6` archives contain `caddy-rs`
> only; the sidecar is packaged in release archives from the next cut after `0.1.0-trial.6`, which is
> the cut this tree is versioned for (`0.1.0-trial.7`). The program repository's `version.json`
> records this under `sidecar.packaged_in_release_archives`. If you are building from source, both
> workspaces are versioned `0.1.0-trial.7`, so a sidecar built from this tree pairs with the
> `caddy-rs` from the same tree.

### Install as a systemd service

`caddy-rs-pm install` writes `/etc/systemd/system/caddy-rs-pm.service`. It must run as root, because
creating the service account and the data directory are privileged operations.

The unit names a service account (default `caddy-rs:caddy-rs`) and a data directory (default
`/var/lib/caddy-rs`) that it makes writable. `install` creates both when they are absent, so a clean
host needs no manual setup — systemd otherwise fails the start with a generic `217/USER` or
`226/NAMESPACE` that never mentions the missing prerequisite:

```sh
sudo install -m 0755 caddy-rs /usr/local/bin/caddy-rs
sudo install -m 0755 caddy-rs-pm /usr/local/bin/caddy-rs-pm
sudo caddy-rs-pm install          # creates the account and data directory if absent
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-rs-pm
```

Every step is idempotent, so re-running `install` is safe: an existing group or user is left
untouched, and an existing data directory keeps its own owner and mode (re-install never changes the
mode of a directory you tightened). If your distribution has no `getent`/`groupadd`/`useradd`
(shadow-utils), create the account first and `install` will find it.

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
the email is); it records the password and TOTP globals, while the email is written into the unit's
`ExecStart` as `--bootstrap-admin-email`. It is root-owned, mode 0600, and
when written the unit references it as `EnvironmentFile=-/etc/caddy-rs-pm.env`: the leading `-`
makes a missing file non-fatal, so a plain install starts without credentials. Installing without
credentials deletes a stale file left by an earlier install. Supply the email and password together:
`serve` creates no administrator unless both are set.

`PM_BOOTSTRAP_ADMIN_TOTP` also works (fixed in T-AUTH-002). The bootstrap enrols a TOTP secret and
then confirms the supplied code against it, so the code must come from the same enrolment. Because
the secret is minted at bootstrap time, the enrolment URI is printed **to the process's stderr** on
success and, if the code is rejected, in the error text on stderr; scan it to keep receiving codes.
The URI embeds the secret, so it is deliberately kept out of the structured log (the log line only
says it was printed, and any `secret=` value in a logged error is replaced by `[redacted]`). Under
systemd stderr is still captured by the journal; where that is not acceptable, enrol TOTP through
`POST /api/v1/auth/totp/setup` after first login instead of using `PM_BOOTSTRAP_ADMIN_TOTP`. A
rejected code removes the administrator it created rather than leaving an account with an unconfirmed
factor.

Pass the bootstrap password and TOTP code through the environment (`PM_BOOTSTRAP_ADMIN_PASSWORD`,
`PM_BOOTSTRAP_ADMIN_TOTP`, i.e. the 0600 environment file `install` writes), not as
`--bootstrap-admin-password` / `--bootstrap-admin-totp`: a command-line argument is visible to every
local user in the process listing and lands in shell history. The flags still work, for backwards
compatibility, but the daemon logs a warning naming the flag whenever one is used.

Two operational constraints follow from the code being time-based. The bootstrap only runs when no
users exist, so this is a first-start-only path: if the code is rejected the administrator is gone
and the next start retries from scratch, which is what makes a retry possible. And a code is valid
only for its 30-second step (plus or minus one step with `totp_window = PlusMinusOne`), so the
service must start within that window of when the code was generated - set the variable and start
the unit immediately, rather than leaving a code in the environment file across a later boot. [pm/README.md](../pm/README.md) describes
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

### Pre-binding privileged ports with the systemd fd store

`bind-fds` lets a privileged helper bind the configured listeners and hand them to `run` through the
systemd fd store, so `run` itself never needs `CAP_NET_BIND_SERVICE`. The helper is idempotent: it
may run from `ExecStartPre` on every start.

#### The fd store cannot be enumerated, and that is a real limitation

systemd does **not** document an interface for listing what the fd store contains. There is no
supported call that answers "which descriptors are stored under which names". This is a limitation
of the systemd interface, not a gap in `caddy-rs`, and the helper does not work around it.

What `bind-fds` does instead, and what you must therefore expect:

- For every name in the current plan it sends `FDSTOREREMOVE=1` followed by `FDSTORE=1`. Removing a
  name that is not stored is a no-op in systemd, so this is safe on a first run.
- Consequently the store converges on **exactly one descriptor per planned listener**, no matter how
  many times the helper runs. It does not accumulate duplicates, but it also cannot tell you whether
  a descriptor it just replaced was previously in use.
- A listener **removed from the configuration** cannot be discovered by the helper, because it
  cannot ask the store what is there. Stale descriptors must be named explicitly; the helper
  provides this as `stale_names(previous, current)` and `remove_stale`, and the unit is responsible
  for supplying the previous plan (for example from the `LISTEN_FDNAMES` it recorded last time).
  **If the previous plan is not supplied, a listener removed from the configuration keeps its
  descriptor and therefore keeps its port** until the unit is fully stopped and the store cleared.

Because there is no enumeration, do not assume `bind-fds` can clean up after a configuration change
it was not told about. Treat the previous plan as required input for that case, and treat the fd
store as a cache keyed by FD name rather than as a queryable registry.

#### Verifying what the store holds

Since the helper cannot list the store, verify from the unit side rather than from the store:

- `bind-fds --dry-run` prints the plan and the FD names it would create, without binding or
  uploading. This is the supported way to check what the next start will do.
- `bind-fds` prints how many descriptors it stored and how many already-stored names it removed and
  re-uploaded, so a re-run for unchanged configuration shows every listener as re-uploaded rather
  than newly uploaded.
- To prove a port was actually released, bind it: a descriptor still held by the store keeps the
  port open, so `bind` failing is the evidence that cleanup did not happen.

#### Reload and restart precedence, and the note to re-check it

Today `caddy-rs` reloads **in process**: a configuration reload keeps the listeners it already has
and does not re-adopt from the fd store. That is the rule this version implements, and it does not
depend on the cross-process handoff design in ADR-0044.

ADR-0044 records a **forward** precedence rule for once that cross-process handoff exists: on reload,
take the handed-off listener first, the fd store second, and bind fresh never. That rule is **not
implemented here** and must not be assumed.

> **Re-check this note when ADR-0044 lands.** When the cross-process handoff is implemented, the
> three-way precedence above supersedes the in-process rule described in this section, and this
> section (and the test that pins the current behaviour) must be updated deliberately rather than
> left to drift. The task that split this work is recorded in the program plan.
