# Command-line reference

`caddy-rs` is one binary with a subcommand for each task. `<command> --help` and
`caddy-rs help <command>` print the same text.

```text
Usage: caddy-rs <COMMAND>

Commands:
  version       Print the version
  build-info    Print information about this build
  list-modules  List modules compiled into this build
  adapt         Adapt a user-facing config to Caddy JSON
  validate      Validate a configuration without running it
  run           Run the server with a configuration
  reload        Load a new configuration into a running server through its admin API
  stop          Stop a running server through its admin API
  environ       Print the environment as seen by this caddy-rs process
  fmt           Formats a Caddyfile
  completion    Generate a shell completion script
  manpage       Generates the manual pages for caddy-rs commands
  pki           Inspect, show and export the local certificate authority material
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

## fmt

Formats a Caddyfile the way `caddy fmt` does: it rewrites bracing, indentation and inter-token
spacing, while leaving words, comments, quoted and backticked strings, escaped characters and
heredocs untouched. The formatter is a port of the pinned Caddy v2.11.9 implementation, and its
output is byte-identical to the oracle for the upstream formatter test corpus and the differential
probe in `.scratch/logs/t-cli-005-oracle/`.

Synopsis: `caddy-rs fmt [--overwrite] [--diff] [<path>]`

| Option | Description | Default |
|---|---|---|
| `-c, --config <CONFIG>` | Configuration file to format. | `Caddyfile` |
| `-w, --overwrite` | Write the formatted result back to the file instead of printing it. | off |
| `-d, --diff` | Print a line diff instead of the formatted file. | off |
| `<path>` | Caddyfile path; `-` reads standard input. | `./Caddyfile` |

```sh
caddy-rs fmt ./Caddyfile                 # preview; fails if the file was not formatted
caddy-rs fmt --overwrite ./Caddyfile     # rewrite in place, exit 0
caddy-rs fmt --diff ./Caddyfile          # show the changes, fail if any
curl -s https://example.com/Caddyfile | caddy-rs fmt -   # stdin -> stdout
```

Behaviour matches Caddy's `cmdFmt`:

- With `--overwrite`, the file is rewritten (mode unchanged) and the command exits 0 without the
  "not formatted" check. `--overwrite` wins over `--diff`.
- With `--diff`, every line is printed with a two-space prefix when unchanged, `- ` when only in
  the input and `+ ` when only in the output. This is not a valid patch format, matching Caddy.
- A path of `-` reads stdin, prints to stdout, and ignores `--overwrite`/`--diff`; the
  "not formatted" check is skipped and the exit status is 0.
- Otherwise the formatted result is printed first. If the input was not already formatted, the
  command then fails with exit 1 and a located message:

  ```text
  caddy-rs: error: ./Caddyfile:3: Caddyfile input is not formatted; Tip: use '--overwrite' to update your Caddyfile in-place instead of previewing it. Consult '--help' for more options
  ```

  The line number is the first byte at which the normalized input (CRLF is compared as LF) differs
  from its formatted form.
- A missing/unreadable file fails with `reading input file: ...`; more than one input (positional
  or `--config` plus a positional) fails with Caddy's `fmt does not support multiple files ...`.

Exit status is 0 on success (including `--overwrite`), 1 when the file cannot be read, when the
input is not formatted, or when multiple inputs are given, and 2 for a clap usage error.

## validate

Checks a configuration without starting the server. The command adapts and parses the file,
validates the result, then builds the serving generation and provisions its modules without binding
sockets or obtaining certificates. A successful check prints `Valid configuration`.

Like Caddy, `validate` provisions the PKI app: a client-auth CA pool that references the implicit
default `local` authority creates (or reuses) `<data-dir>/pki/authorities/local` under the resolved
data directory (`--data-dir`, `storage.root`, `CADDY_RS_DATA_DIR`, or Caddy's XDG data path) even
though no listener is bound.

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
| `--autosave-path <PATH>` | Autosave file to write, and to load with `--resume`. | `$XDG_CONFIG_HOME/caddy/autosave.json`, else `$HOME/.config/caddy/autosave.json`, else `./caddy/autosave.json`; a legacy caddy-rs autosave is used only when the Caddy path is absent |
| `--data-dir <PATH>` | Certificate/account/pki data directory. | Caddy's `$XDG_DATA_HOME/caddy`/`$HOME/.local/share/caddy`, with legacy `.caddy-rs` fallback |
| `--envfile <PATH>` | Load `KEY=VALUE` environment file(s) before adaptation. | none |
| `-e, --environ` | Print the environment before starting. | off |

```sh
caddy-rs run --config ./Caddyfile --adapter caddyfile
```

With no `--config`, `run` loads `./Caddyfile` when it exists, matching stock Caddy. Pass
`--config`, or `--resume` when an autosave file exists. `--resume` loads the autosave file when one
exists and warns that it is ignoring `--config` if you passed both. A missing autosave file is not
an error; `run` falls back to `--config`.

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

`caddy-rs pki` is a caddy-rs extension. Stock Caddy v2.11.9 has no `pki` CLI (`cmd/pki*.go` does not
exist); Caddy's CA surface is the admin API `GET /pki/ca/<id>` and `GET /pki/ca/<id>/certificates`
(`modules/caddypki/adminapi.go`). The storage layout is Caddy's `caddypki` layout
(`<data-dir>/pki/authorities/<id>/{root,intermediate}.{crt,key}`), the `--json` CA fields use
Caddy's `caInfo` names, and chains are ordered intermediates first, root last, exactly like
`/pki/ca/<id>/certificates`.

The data directory is resolved exactly as the server resolves it: a configured `storage.root` from
`--config` (the storage the server writes), then `--data-dir`, then `$CADDY_RS_DATA_DIR`, then
Caddy's `AppDataDir()` (`$XDG_DATA_HOME/caddy`, `$HOME/.local/share/caddy`, platform variants), with
the legacy `.caddy-rs` working-directory directory when it already exists. A missing or unreadable
data directory is an error that names the path and how it was chosen; an existing but empty one is
the normal "no CA provisioned yet" state.

Synopsis: `caddy-rs pki <COMMAND>`

| Command | Purpose |
|---|---|
| `list` | List the local certificate authorities. |
| `show <ID>` | Show one CA: subjects, validity, key files and trust state. |
| `export <ID>` | Export one CA certificate or chain as PEM. |

### pki list

Prints one row per certificate authority, with the columns `ID`, `ROOT_CN`, `INTERMEDIATE_CN`,
`ROOT_EXPIRES`, `INTERMEDIATE_EXPIRES` and `TRUST`.

`TRUST` is the read-only state of the platform trust store for the CA root: `installed` (the
platform install target contains this exact root certificate and, on Linux, the generated
`/etc/ssl/certs/ca-certificates.crt` bundle does not contradict it), `missing` (the target does not
contain it, or the bundle is stale), `disabled` (the supplied configuration has
`apps.pki.certificate_authorities.<id>.install_trust: false`) or `unknown` (the platform store
cannot be inspected without installing, as on macOS and Windows, or the platform tool is
unavailable). On Linux the checked install target is
`/usr/local/share/ca-certificates/caddy-rs-<id>.crt`. NSS/Firefox and Java stores are not queried by
`list`; use `caddy-rs trust --dry-run` to see every target.

Synopsis: `caddy-rs pki list [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | server resolution (see above) |
| `--config <CONFIG>` | Configuration whose `storage.root` and `apps.pki` `install_trust` settings apply. | none |
| `--adapter <ADAPTER>` | Adapter for `--config`. | inferred |
| `--json` | Machine-readable JSON output. | off |

```sh
caddy-rs pki list
caddy-rs pki list --json
caddy-rs pki list --config /etc/caddy/Caddyfile
```

An empty authorities directory prints
`no local certificate authorities under <authorities-dir> (data directory <data-dir>)` and exits 0.

The JSON form includes `data_dir`, `authorities_dir` and an `authorities` array. Each entry has
`id`, `directory`, `root_common_name`, `intermediate_common_name`, `root_not_after`,
`intermediate_not_after`, `has_intermediate` and `trust` (`state` and `install_trust`).

Exit status is 0 on success, 1 when the data directory is missing/unreadable or cannot be listed,
and 2 for usage errors.

### pki show

Shows one CA in detail: the CA id, name (Caddy's configured `apps.pki...name` when `--config` is
supplied, otherwise the id), directory, platform trust state, the root certificate's subject,
issuer, serial, validity and key file, and each intermediate certificate with the same fields.
`key` reports whether `<ca>/root.key` / `<ca>/intermediate.key` exists; the key material itself is
never read or printed.

Synopsis: `caddy-rs pki show [OPTIONS] <ID>`

| Option | Description | Default |
|---|---|---|
| `<ID>` | CA identifier, for example `local`. | required |
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | server resolution (see above) |
| `--config <CONFIG>` | Configuration whose `storage.root`, CA name and `install_trust` settings apply. | none |
| `--adapter <ADAPTER>` | Adapter for `--config`. | inferred |
| `--json` | Machine-readable JSON output. | off |

```sh
caddy-rs pki show local
caddy-rs pki show local --json
```

`--json` prints Caddy's `caInfo` fields (`id`, `name`, `root_common_name`,
`intermediate_common_name`, `root_certificate`, `intermediate_certificate`) plus `directory`,
`root`, `intermediates` (1-based `index`, subject, issuer, serial, validity, DNS names, key path)
and `trust`. A missing CA or an unknown id is an error that reports the directory it looked in.

### pki export

Exports one certificate or certificate chain as PEM. The default is the root certificate. PEM is
written byte-for-byte, so `--out` produces the same bytes as Caddy's `root.crt`/`intermediate.crt`
(and stdout can be piped directly).

Synopsis: `caddy-rs pki export [OPTIONS] <ID>` or `caddy-rs pki export --ca <ID> ...`

| Option | Description | Default |
|---|---|---|
| `<ID>` | CA identifier, for example `local`; alternative to `--ca`. | required (one of them) |
| `--ca <ID>` | CA identifier; same as the positional `<ID>`. | required (one of them) |
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | server resolution (see above) |
| `--config <CONFIG>` | Configuration whose `storage.root` applies. | none |
| `--adapter <ADAPTER>` | Adapter for `--config`. | inferred |
| `--type <TYPE>` | `root`, `intermediate` or `chain`. | `root` |
| `--out <PATH>` | Write the PEM to a file instead of standard output. | stdout |
| `--root` | Alias for `--type root` (kept for compatibility). | — |
| `--intermediate` | Alias for `--type intermediate`. | off |
| `--chain` | Alias for `--type chain`, intermediates first and root last. | off |

`--type` cannot be combined with the alias flags, and the positional `<ID>` cannot be combined with
`--ca`. `--out` does not create missing parent directories; a missing directory is a located error
and no file is written.

```sh
caddy-rs pki export local > local-root.crt
caddy-rs pki export --ca local --type intermediate --out local-intermediate.crt
caddy-rs pki export --ca local --type chain --out local-chain.crt
```

The CA must already exist in the data directory. A missing CA is an error that reports the path it
looked in; exporting the intermediate of a root-only CA is also an error rather than an empty file.

Exit status is 0 on success, 1 when the data directory/CA is missing or the output cannot be
written, and 2 for usage errors (missing/ambiguous CA selector, unknown `--type`, conflicting
flags).

## trust

Installs the local CA root certificate into host trust stores. The command works directly from the
data directory, so no running server is required. The CA must already exist in the data directory;
`trust` never creates it. The command plans an update for the platform store, each discovered
NSS/Firefox database and each discovered Java `cacerts` keystore.

Synopsis: `caddy-rs trust [OPTIONS]`

| Option | Description | Default |
|---|---|---|
| `--data-dir <DATA_DIR>` | Data directory containing `pki/authorities`. | server resolution (same as `pki`) |
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

## completion

Generates and installs shell completion scripts. The scripts are produced from this binary's clap
command tree, so every compiled subcommand and flag is covered.

```text
caddy-rs completion bash|zsh|fish|powershell   # print the script on stdout
caddy-rs completion install                    # install every detected shell
caddy-rs completion install --shell zsh        # install one shell (repeatable or comma-separated)
caddy-rs completion uninstall                  # remove files installed by this tool
caddy-rs completion uninstall --shell zsh      # remove one shell's file
caddy-rs completion status                     # show detection, target paths and state
```

`--shell` accepts `bash`, `zsh`, `fish` and `powershell` (case-insensitive) and may be repeated or
given a comma-separated list (`--shell bash,zsh`). An unknown value is a usage error that names the
accepted set. Without `--shell`, `install` covers every **detected** shell and `uninstall` visits
every known target path, so a file remains removable after the shell configuration that led to its
installation is gone. Both commands accept `--dry-run`, which prints the same `would install`,
`would update`, `already up to date`, `would remove` and `not installed` lines without creating,
updating or deleting anything.

### Install locations

`XDG_DATA_HOME` and `XDG_CONFIG_HOME` are used when set; otherwise the conventional home paths:

| Shell | Target path |
|---|---|
| bash | `${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/caddy-rs` |
| zsh | `${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_caddy-rs` |
| fish | `${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/caddy-rs.fish` |
| powershell | `${XDG_CONFIG_HOME:-$HOME/.config}/powershell/Completions/caddy-rs.ps1` |

Parent directories are created as needed. The zsh default is `site-functions`, which standard
distributions put on `$fpath`. Oh My Zsh users may instead need
`~/.oh-my-zsh/completions/_caddy-rs`; the command detects `~/.oh-my-zsh` as evidence that zsh is in
use but deliberately keeps `site-functions` as the write target. PowerShell users must dot-source
the installed file from their own `$PROFILE`, for example:

```powershell
. "$HOME/.config/powershell/Completions/caddy-rs.ps1"
```

`completion install` never edits `$PROFILE`, `.bashrc`, `.zshrc` or any other shell rc file, and
`completion uninstall` never reads them either.

### Detection rules

A shell is detected when the first matching rule below applies. `status` prints the rule that
matched. A shell binary on `PATH` is **not** evidence for bash, zsh or fish: a binary without a
configuration would produce a file the shell never loads.

| Shell | Rules, in order |
|---|---|
| bash | basename of `$SHELL` is `bash`; `~/.bashrc` exists; `~/.bash_completion` exists |
| zsh | basename of `$SHELL` is `zsh`; `~/.oh-my-zsh` exists; `~/.zshrc` exists |
| fish | basename of `$SHELL` is `fish`; the fish config directory exists (`$XDG_CONFIG_HOME/fish`, else `~/.config/fish`) |
| powershell | basename of `$SHELL` is `pwsh` or `powershell`; an executable `pwsh` is on `PATH`; `~/.config/powershell` exists |

The `pwsh`-on-`PATH` rule is the one deliberate binary exception: `pwsh` only appears after an
explicit PowerShell installation.

### Ownership marker and status states

Every installed file starts with this first line:

```text
# generated by caddy-rs completion install; safe to delete with 'caddy-rs completion uninstall'
```

`install` is idempotent: re-running over identical bytes reports `already up to date` and writes
nothing; a file whose first line is not the marker is never overwritten (exit 1, naming the path).
`uninstall` removes a file only when that marker is its first line; otherwise it refuses with exit 1
and prints `refusing to remove <path>: not installed by caddy-rs`. A refused file is left untouched,
and a bare `uninstall` still removes the other owned files it finds.

`status` prints, for each of the four shells, whether it was detected and the matching rule, the
target path, and one of these states:

| State | Meaning |
|---|---|
| `not installed` | no owned file exists at the target path (a foreign file is called out in a `note:`) |
| `installed` | the file starts with the marker and its bytes equal the current generated script |
| `stale` | the file starts with the marker but differs from the current generated script, typically after a binary upgrade; re-run `install` to refresh it |

`status` exits 0 unless a target path cannot be read.

### Installer guidance

Any future installer — a distribution package, container image or desktop app — should call
`caddy-rs completion install` as the user who will use the shell instead of hard-coding one shell.
That covers every detected shell and preserves the marker/ownership contract that makes
`uninstall` safe. Running the command with elevated privileges (`sudo`, `docker exec -u root`)
installs into root's home, not the user's; run it as the target user.

Exit status is 0 on success and 1 for an operational failure (no detected shell, an unwritable
directory, refusal to overwrite or remove a non-owned file) or an unknown `--shell` value. A
`--shell` or `--dry-run` flag used with plain script generation or with `status` is also a usage
error.

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
| `CADDY_RS_DATA_DIR` | `run`, `pki`, `trust` | Data directory when `--data-dir` is absent. |
| `XDG_DATA_HOME` | `run`, `completion` | Base for Caddy's default data directory; bash/zsh completion install location. |
| `XDG_CONFIG_HOME` | `run`, `completion` | Base for the default autosave path; fish/PowerShell completion install location. |
| `HOME` | `run`, `trust`, `completion` | Fallback base for the autosave path; home directory for NSS/Firefox discovery in `trust`; base for completion paths and detection dot-directories. |
| `SHELL` | `completion` | Detection rule: its basename names the shell in use. |
| `CADDY_RS_TRUST_PREFIX` | `trust` | Prefix for platform trust-store paths, default `/`. Intended for tests and containers. |
| `JAVA_HOME` | `trust` | Java installation whose keystore is discovered. |
| `PATH` | `trust`, `completion` | Locates the tools used to update trust stores; finds an executable `pwsh` for PowerShell detection. |
| `LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES` | `run` | systemd socket activation. |

The configuration's `storage.root` also sets the data directory for `run`, and for `trust` when
`--config` is given.
