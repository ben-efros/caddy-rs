# T-CLI-010 compatibility note — `caddy-rs storage`

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task adds the `storage export` and `storage import` subcommands. The note below states only
behaviour this implementation can point at a test or an oracle measurement for; the proposed
register entry is at the end.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- `cmd/commands.go` (lines 331-380) — the `storage` parent command registration: the short text
  `Commands for working with Caddy's storage (EXPERIMENTAL)`, the long text with the stdout/stdin
  pipeline example, the file_system ownership NOTE and the EXPERIMENTAL warning, and the `export`
  (`Exports storage assets as a tarball`, `--config/-c`, `--output/-o`) and `import` (`Imports
  storage assets from a tarball.`, `--config/-c`, `--input/-i`) children. Neither flag is marked
  required in the registration; the handlers enforce it.
- `cmd/main.go::isCaddyfile` — adapter inference used by `LoadConfig` when no adapter is given:
  a `.json` extension is JSON; otherwise a base name starting with `caddyfile`
  (case-insensitive) or ending in `.caddyfile` is the Caddyfile adapter; anything else is JSON.
- `cmd/storagefuncs.go::determineStorage` — reads `--config` with that inferred adapter and returns
  the config's `storage` object (or nil for the default `file_system` storage). It does not
  provision or validate the rest of the configuration.
- `cmd/storagefuncs.go::cmdExportStorage` — `--config`/`--output` checks (`--config is required`,
  `--output is required`, exit 1), `stor.List(ctx, "", true)`, then one tar entry per key with
  `Name: key`, `Mode: 0600`, `Size` and `ModTime: info.Modified`; `Stat` failures that are
  `fs.ErrNotExist` log `key: %s removed while export is in-progress` and continue, and every other
  failure after startup is `ExitCodeFailedQuit` (3). The output is opened only after listing
  ("opening output file"); `-` means stdout.
- `cmd/storagefuncs.go::cmdImportStorage` — `--config`/`--input` checks (exit 1), input opened
  after `determineStorage` ("opening input file", exit 1), then a `tar.Reader` loop
  `stor.Store(ctx, hdr.Name, b)` until EOF; read/store failures are `ExitCodeFailedQuit` (3) with
  the `reading archive: ` prefix, and success prints `Successfully imported storage`. `-` means
  stdin.
- `sigtrap.go` — `ExitCodeSuccess = 0`, `ExitCodeFailedStartup = 1`, `ExitCodeFailedQuit = 3`.
- `modules/filestorage/filestorage.go` — a `file_system` key is the slash-separated path of a file
  below `Root`; `List("", true)` walks the tree (lexical order) and reports regular files as
  terminal keys, directories are not terminal, and `Store` writes values through owner-only files.

## Implemented behaviour

`crates/cli/src/storage.rs` reimplements both commands against the `file_system` storage module
(the only module this build has, and Caddy's default). The configuration is adapted with Caddy's
`isCaddyfile` rule and decoded as `caddy_rs_core::Config` — not provisioned, like
`determineStorage` — and the storage root is its `storage.root`, else the data directory resolved
by `caddy_rs_core::data_dir::resolve_server_data_dir`. The commands accept no `--adapter` and no
`--data-dir`, matching upstream.

| Input | Result |
|---|---|
| `storage --help`, `storage export --help`, `storage import --help` | upstream usage, about/long text and flag docs |
| `storage` (no subcommand) | long help on stdout, exit 0 (cobra prints the parent help) |
| `storage export -c cfg -o storage.tar` | tar of every regular file below the root, keys lexically sorted |
| `storage export -c cfg -o -` | archive on stdout |
| export entry headers | `Name` = slash-separated key, `Mode` = 0600, `Size`, `ModTime` in whole seconds |
| `storage import -c cfg -i storage.tar` | files recreated below the root, parents created, mode 0600, prints `Successfully imported storage` |
| `storage import -c cfg -i -` | reads the archive from stdin |
| re-import of an existing key | contents replaced and mode reset to 0600 |
| empty input archive | no-op success, `Successfully imported storage` |
| archive key with `../` or an absolute path | exit 3, `reading archive: refusing key ...`, nothing written outside the root |
| archive key with a `./` prefix | cleaned to the same relative key (Go `filepath.Join` behaviour) |
| non-tar input | exit 3, `reading archive: ...` |
| missing `--config`/`--output`/`--input` | exit 1, `--config is required` / `--output is required` / `--input is required` |
| missing `--config` file | exit 1, `cannot read config <path>` |
| missing `--input` file | exit 1, `opening input file <path>` |
| storage root that does not exist | exit 1, `cannot list storage <root>`; the output file is not created or truncated |
| unwritable output path | exit 1, `opening output file <path>` |
| configured `storage.module` other than `file_system` | exit 1, `unsupported storage module <module>; this build implements only file_system` |
| config `storage.root` | that root, ahead of the data directory |
| config without `storage` (JSON `{}` or a Caddyfile) | Caddy's default data directory (`$XDG_DATA_HOME/caddy`, …) |

Tests: `crates/cli/tests/cli.rs` `storage_help_matches_caddys_usage_and_flags`,
`storage_export_writes_a_sorted_tar_of_the_storage_tree`,
`storage_export_to_stdout_and_import_from_stdin_round_trip`,
`storage_import_writes_files_with_owner_only_mode`,
`storage_requires_config_and_output_or_input_flags`,
`storage_export_fails_when_the_storage_root_is_missing_and_leaves_the_output_alone`,
`storage_export_writes_an_empty_archive_for_an_empty_root`,
`storage_rejects_an_unsupported_storage_module`,
`storage_import_refuses_archive_keys_outside_the_root`,
`storage_import_reports_a_non_tar_input_and_leaves_the_root_empty`,
`storage_accepts_an_empty_archive_as_a_successful_no_op`,
`storage_defaults_to_the_caddy_data_directory`, `storage_accepts_a_caddyfile_config`,
`storage_export_reports_an_unwritable_output_path`,
`storage_import_cleans_a_dot_prefixed_archive_key_into_the_root`.

## Residual divergences

1. Only the `file_system` module is implemented; any other `caddy.storage` module (for example
   `s3`) is a located exit-1 error instead of a working backend. This is the module surface of this
   build, not an `storage` command gap.
2. Archive entry names that are empty, absolute or contain `..` are refused before they reach the
   store, where Caddy passes `hdr.Name` straight to `Store` (a certmagic file storage key is joined
   onto the root, so such names can escape it).
3. Archive entries are written as GNU tar headers (the `tar` crate) where Go picks USTAR/PAX; both
   are readable by Caddy and by system `tar`, and the entry metadata matches.
4. Modification times are whole seconds, as in Go's `tar.Header.ModTime` on a filesystem that
   stores sub-second times.
5. Warnings are plain `warning: ...` lines, not Caddy's JSON zap log records.
6. Errors are caddy-rs located errors (`name the path`) where the upstream messages use Go's
   `open <path>: ...` wording; the exit code and the operation named are the same.
7. A storage key that is not valid UTF-8 cannot be listed (exit 1) or imported (exit 3); Go's tar
   names are bytes.
8. Both storage commands start with no adapter inference other than the `isCaddyfile` basename
   rule, so a config file with an unrecognised name is read as JSON (Caddy behaves the same for
   these commands, which pass an empty adapter).

## Proposed register entry (program repository)

```text
## DIV-0119 — `storage` implements only file_system storage and refuses archive keys outside the root

- Area: CLI
- Caddy behaviour: `caddy storage export`/`caddy storage import` load whatever `caddy.storage`
  module the configuration names (`ctx.LoadModule`), and `import` passes every tar entry name
  straight to `certmagic.Storage.Store`, so a `../` or absolute name is joined onto the storage
  root and can be written outside it. Under `file_system` storage, `List("", true)` walks the root
  in lexical order and reports every regular file as a terminal key.
- caddy-rs behaviour: only `file_system` (and `caddy.storage.file_system`) is accepted; any other
  module is exit 1 `unsupported storage module <module>; this build implements only file_system`.
  Export writes every regular file below the root as a GNU tar entry named by its slash-separated
  key, mode 0600, whole-second mtime, lexically sorted, listing the keys before the output is
  opened. Import validates each entry name and exits 3 with `reading archive: refusing key ...`
  for empty, absolute or `..` names before writing anything; a `./` prefix is cleaned to the same
  relative key. Values are written with mode 0600 and parents created, and success prints
  `Successfully imported storage`.
  Exit codes: 0 success, 1 failed startup (flags, config, module, listing, input/output open),
  3 failed quit (archive read/write/store).
- Rationale: This build has no s3/azure/gcs storage backend, so claiming to export or import them
  would be a silent approximation; a located error is the advertised unsupported outcome. Refusing
  unsafe archive names prevents an archive from writing outside the configured storage root, which
  the upstream code leaves to the storage backend and the operator's trust in the archive.
- Status: divergent
- Tracking: T-CLI-010
- Test: `crates/cli/tests/cli.rs` `storage_rejects_an_unsupported_storage_module`,
  `storage_import_refuses_archive_keys_outside_the_root`,
  `storage_import_cleans_a_dot_prefixed_archive_key_into_the_root`,
  `storage_export_writes_a_sorted_tar_of_the_storage_tree`,
  `storage_import_writes_files_with_owner_only_mode`,
  `storage_help_matches_caddys_usage_and_flags`,
  `storage_requires_config_and_output_or_input_flags`
```
