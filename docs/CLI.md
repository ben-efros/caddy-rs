# Command-line reference

`caddy-rs` is one binary with a subcommand for each task. `<command> --help` and
`caddy-rs help <command>` print the same text.

```text
Usage: caddy-rs <COMMAND>

Commands:
  version       Print the version
  list-modules  List modules compiled into this build
  adapt         Adapt a user-facing config to Caddy JSON
  validate      Validate a configuration without running it
  run           Run the server with a configuration
  reload        Load a new configuration into a running server through its admin API
  stop          Stop a running server through its admin API
  pki           Inspect and export the local certificate authority material
  trust         Install the local CA root certificate into the host trust stores
  help          Print this message or the help of the given subcommand(s)
```

There is no global `--version` flag; use the `version` subcommand.

The examples assume `caddy-rs` is on your `PATH`. When running from a build directory, use
`./target/release/caddy-rs` instead.

`--adapter` selects the configuration format: `caddyfile` or `json`. When it is omitted, a file
whose name starts with `Caddyfile` is read as a Caddyfile and every other file is read as JSON. Any
other adapter name is rejected with an error.

`--adapt-mode` selects how strictly the **Caddyfile** adapter treats deprecated spellings:
`compatible` (the default) accepts them and prints Caddy's deprecation warning, `warn` accepts them
as a superset of `compatible` (adding warnings for future ambiguity gates), and `strict` rejects
them with a located error naming both the deprecated and the current spelling. The mode is a caddy-rs extension (Caddy has no equivalent flag); it governs
configuration-acceptance strictness only and never relaxes a security rejection. It is available on
`adapt`, `validate` and `run`; the JSON adapter ignores it.

## version

Prints the build version and the Caddy configuration baseline it targets.

Synopsis: `caddy-rs version [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--json` | Machine-readable output. | off |

```sh
caddy-rs version
```

```text
caddy-rs 0.1.0 (Caddy configuration baseline v2.11.9)
```

```sh
caddy-rs version --json
```

```json
{"caddy_compat_baseline":"v2.11.9","version":"0.1.0"}
```

Exit status is 0.

## list-modules

Lists the modules compiled into this build, by module id.

Synopsis: `caddy-rs list-modules [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--json` | Machine-readable output. | off |

```sh
caddy-rs list-modules
```

The plain form prints one module id per line, for example `http.handlers.reverse_proxy`. The JSON
form prints one object with a `modules` array; each entry has `id`, `json_key`, `kind` and
`summary`:

```sh
caddy-rs list-modules --json > modules.json
```

Exit status is 0.

## adapt

Converts a configuration to Caddy JSON and writes it to standard output or to a file. Adapter
warnings are printed to standard error as `warning: ...`.

Synopsis: `caddy-rs adapt [OPTIONS] --config <CONFIG>`

| Option | Description | Default |
|---|---|---|
| `-c, --config <CONFIG>` | Configuration file to read. | required |
| `--adapter <ADAPTER>` | `caddyfile` or `json`; inferred from the file name when omitted. | inferred |
| `--adapt-mode <MODE>` | Caddyfile acceptance mode: `compatible`, `warn` or `strict`. | `compatible` |
| `--pretty` | Indent the JSON output. | off |
| `-o, --output <OUTPUT>` | Write the JSON to a file instead of standard output. | standard output |

```sh
caddy-rs adapt --config ./Caddyfile --adapter caddyfile --pretty --output ./caddy.json
```

The command converts the input; it does not check that the result can run. Use `validate` on the
adapted file for that.

Exit status is 0 on success, 1 when the file cannot be read or adapted, and 2 for a usage error.

## validate

Checks a configuration without starting the server. The command adapts and parses the file,
validates the result, then builds the serving generation and provisions its modules without binding
sockets or obtaining certificates. A successful check prints `Valid configuration`.

Synopsis: `caddy-rs validate [OPTIONS] --config <CONFIG>`

| Option | Description | Default |
|---|---|---|
| `-c, --config <CONFIG>` | Configuration file to read. | required |
| `--adapter <ADAPTER>` | `caddyfile` or `json`; inferred from the file name when omitted. | inferred |
| `--adapt-mode <MODE>` | Caddyfile acceptance mode: `compatible`, `warn` or `strict`. | `compatible` |

```sh
caddy-rs validate --config ./caddy.json --adapter json
```

Exit status is 0 when the configuration is valid and 1 when it is not. Validation errors name the
file and the offending line or field.

## run

Starts the server with a configuration and keeps running in the foreground.

Synopsis: `caddy-rs run [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `-c, --config <CONFIG>` | Configuration file to read. | none |
| `--adapter <ADAPTER>` | `caddyfile` or `json`; inferred from the file name when omitted. | inferred |
| `--adapt-mode <MODE>` | Caddyfile acceptance mode: `compatible`, `warn` or `strict`. | `compatible` |
| `-r, --resume` | Load the last autosave file, preferring it over `--config`. | off |
| `--autosave-path <PATH>` | Autosave file to write, and to load with `--resume`. | `$XDG_CONFIG_HOME/caddy-rs/autosave.json`, else `$HOME/.config/caddy-rs/autosave.json`, else `./.caddy-rs/autosave.json` |

```sh
caddy-rs run --config ./Caddyfile --adapter caddyfile
```

Pass `--config`, or `--resume` when an autosave file exists. With neither, the command exits 1 with
`no configuration to load`. `--resume` loads the autosave file when one exists and warns that it is
ignoring `--config` if you passed both. A missing autosave file is not an error; `run` falls back to
`--config`.

After a configuration loads, `run` writes the exact JSON it loaded to the autosave file and prints
that path. It also prints the active generation, every listening address and the admin API address
to standard error.

The first SIGINT or SIGTERM starts a graceful shutdown; a second signal closes connections
immediately. `caddy-rs stop` shuts the process down through the admin API. The Caddyfile global
option `admin off` (or `admin.disabled: true` in JSON) turns the admin API off.

Exit status is 0 after a clean shutdown and 1 when the configuration cannot be loaded or a listener
cannot be started.

## reload

Loads a new configuration into a running server through its admin API.

Synopsis: `caddy-rs reload [OPTIONS] --config <CONFIG>`

| Option | Description | Default |
|---|---|---|
| `-c, --config <CONFIG>` | Configuration file to read. | required |
| `--adapter <ADAPTER>` | `caddyfile` or `json`; inferred from the file name when omitted. | inferred |
| `--admin <ADMIN>` | Admin API address. | `localhost:2019` |

```sh
caddy-rs reload --config ./Caddyfile --adapter caddyfile
```

The new configuration is validated locally first, then posted to `/load` on the admin API. The
running server keeps listeners whose address did not change, so a reload does not create a
listening gap. On success the command prints `configuration reloaded` to standard error.

`--admin` takes a `host:port` pair; an `http://` prefix is accepted. Use it when the server's
`admin.listen` is not the default.

Exit status is 0 when the server accepts the configuration and 1 when the configuration is invalid,
the admin API cannot be reached, or the server rejects the load.

## stop

Stops a running server through its admin API.

Synopsis: `caddy-rs stop [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--admin <ADMIN>` | Admin API address. | `localhost:2019` |

```sh
caddy-rs stop
```

The command posts to `/stop` and prints `server stopped` to standard error.

Exit status is 0 when the server accepts the request and 1 when the admin API cannot be reached or
rejects it.

## pki

Inspects and exports the local certificate authority material stored in the data directory. These
commands only read the data directory; the CA is created by the server when it issues a certificate
with the internal issuer.

Synopsis: `caddy-rs pki <COMMAND>`

| Command | Purpose |
|---|---|
| `list` | List the local certificate authorities. |
| `export <ID>` | Export one CA certificate as PEM. |

### pki list

Prints one row per certificate authority, with the columns `ID`, `ROOT_CN`, `INTERMEDIATE_CN`,
`ROOT_EXPIRES` and `INTERMEDIATE_EXPIRES`. An empty data directory prints
`no local certificate authorities under ...` and still exits 0.

Synopsis: `caddy-rs pki list [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | `$CADDY_RS_DATA_DIR` or `.caddy-rs` |
| `--json` | Machine-readable JSON output. | off |

```sh
caddy-rs pki list
caddy-rs pki list --json
```

The JSON form includes `data_dir`, `authorities_dir` and an `authorities` array. Each entry has
`id`, `directory`, `root_common_name`, `intermediate_common_name`, `root_not_after`,
`intermediate_not_after` and `has_intermediate`.

Exit status is 0 on success and 1 when the data directory cannot be read.

### pki export

Exports one certificate or certificate chain as PEM to standard output.

Synopsis: `caddy-rs pki export [OPTIONS] <ID>`

| Option | Description | Default |
|---|---|---|
| `<ID>` | CA identifier, for example `local`. | required |
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | `$CADDY_RS_DATA_DIR` or `.caddy-rs` |
| `--root` | Export the root certificate; this is the default export. | — |
| `--intermediate` | Export the intermediate certificate chain only. | off |
| `--chain` | Export the full chain, intermediates first and root last. | off |

`--root`, `--intermediate` and `--chain` are mutually exclusive.

```sh
caddy-rs pki export local > local-root.crt
```

The CA must already exist in the data directory. A missing CA is an error that reports the path it
looked in.

Exit status is 0 on success and 1 when the data directory cannot be read or the CA does not exist.

## trust

Installs the local CA root certificate into host trust stores. The command works directly from the
data directory, so no running server is required. The CA must already exist in the data directory;
`trust` never creates it. The command plans an update for the platform store, each discovered
NSS/Firefox database and each discovered Java `cacerts` keystore.

Synopsis: `caddy-rs trust [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | `$CADDY_RS_DATA_DIR` or `.caddy-rs` |
| `--ca <CA>` | CA identifier. | `local` |
| `--config <CONFIG>` | Configuration whose `apps.pki` `install_trust` and `storage.root` settings apply. | none |
| `--adapter <ADAPTER>` | Adapter for `--config`. | inferred |
| `--dry-run` | Print the exact commands and paths without modifying any trust store. | off |

```sh
caddy-rs trust --dry-run
```

Review the printed commands, then install:

```sh
sudo caddy-rs trust
```

On Linux the platform store is updated with `update-ca-certificates`, so the command needs the
privileges of the printed commands. Stores whose tool is missing are reported with their
limitation. With `--config`, a CA configured with
`apps.pki.certificate_authorities.<id>.install_trust: false` is a no-op with a message, and the
configured `storage.root` is used as the data directory.

Exit status is 0 on success, including `--dry-run` and the `install_trust: false` no-op, and 1 when
no trust store could be updated or the CA does not exist.

## Exit codes and errors

| Code | Meaning |
|---|---|
| 0 | The command succeeded. |
| 1 | The command failed: invalid configuration, unreachable admin API, missing CA, failed trust-store update, and similar. |
| 2 | Command-line usage error: missing required argument, unknown option, or conflicting options. |

Errors from the configuration model are printed as:

```text
caddy-rs: error[<code>]: <message>
```

The code is stable and machine-readable, for example:

```text
caddy-rs: error[config.invalid]: cannot adapt `./Caddyfile`: invalid configuration at `Caddyfile line 2`: unterminated quoted string before newline
caddy-rs: error[module.unknown]: `./caddy.json` is not a valid configuration: unknown HTTP handler module `nope` at `apps.http.servers.srv0.routes[0].handle[0].handler`
```

The codes include `config.invalid`, `config.unsupported`, `config.json`, `config.io`,
`listen.invalid`, `module.unknown`, `module.duplicate`, `module.key_conflict`,
`module.invalid_definition`, `not_implemented`, and the `lifecycle.*` codes.

Other failures are printed without a code:

```text
caddy-rs: error: cannot read config `./missing.json`: No such file or directory (os error 2)
caddy-rs: error: unsupported adapter `yaml`; supported adapters are caddyfile and json
```

Warnings go to standard error and do not change the exit status.

## Environment

| Variable | Read by | Effect |
|---|---|---|
| `CADDY_RS_DATA_DIR` | `pki`, `trust` | Data directory when `--data-dir` is absent. |
| `XDG_CONFIG_HOME` | `run` | Base for the default autosave path. |
| `HOME` | `run`, `trust` | Fallback base for the autosave path; home directory for NSS/Firefox discovery in `trust`. |
| `CADDY_RS_TRUST_PREFIX` | `trust` | Prefix for platform trust-store paths, default `/`. Intended for tests and containers. |
| `JAVA_HOME` | `trust` | Java installation whose keystore is discovered. |
| `PATH` | `trust` | Locates the tools used to update trust stores. |
| `LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES` | `run` | systemd socket activation. |

The configuration's `storage.root` also sets the data directory for `run`, and for `trust` when
`--config` is given.
