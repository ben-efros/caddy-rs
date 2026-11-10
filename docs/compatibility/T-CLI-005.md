# T-CLI-005 compatibility note — `caddy-rs fmt` matches Caddy v2.11.9

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task adds the `fmt` subcommand with byte-identical formatting; the only differences are the
CLI-wide diagnostic envelope and clap's usage-error exit code, both already accepted under
DIV-0023. The exact proposed register text is at the end of this note.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- `cmd/commands.go` — `fmt` command registration: `Usage: "[--overwrite] [--diff] [<path>]"`,
  flags `-c/--config`, `-w/--overwrite`, `-d/--diff`, and the long help text.
- `cmd/commandfuncs.go::cmdFmt` — input selection (`--config` vs positional vs default
  `Caddyfile`), the multi-input rejection, the `-` stdin special case, `--overwrite` (exit 0, no
  formatting check), `--diff` (aryann/difflib line diff), and the post-print
  `caddyfile.FormattingDifference` failure with `file:line`.
- `caddyconfig/caddyfile/formatter.go::Format` — the rune-by-rune formatting state machine.
- `caddyconfig/caddyfile/adapter.go::FormattingDifference` — CRLF normalization and the first
  differing line number.
- `caddyconfig/caddyfile/lexer.go::isHeredocMarker` — heredoc marker valid characters.
- `github.com/aryann/difflib.Diff` (v0.0.0-20210328193216-ff5ff6dc229b, in the module cache) — the
  LCS line diff used by `--diff`.

## Implemented behaviour

`crates/cli/src/fmt.rs` is a line-for-line port of the formatter state machine (words, comments,
single/double/backtick quoting and the `"`/`` ` `` combinations, escapes, heredoc open/close,
brace folding, top-level `import` spacing, the nesting cap of 10, trailing-newline trimming). The
command layer mirrors `cmdFmt`:

| Input | Result |
|---|---|
| `fmt <path>` | formatted bytes to stdout; then exit 1 + located message if the file was not formatted, else 0 |
| `fmt --overwrite <path>` | rewrite the file in place, no stdout, exit 0 (the check is skipped) |
| `fmt --overwrite --diff <path>` | overwrite wins, exit 0 |
| `fmt --diff <path>` | all lines printed with `  `/`- `/`+ ` prefixes, then the same exit-1 check |
| `fmt -` | stdin to stdout, exit 0, `--overwrite`/`--diff` ignored, check skipped |
| `fmt` | `./Caddyfile` |
| `fmt -c <path>` | that path |
| >1 positional, or `--config` and a positional | `fmt does not support multiple files <config> <args>` (Caddy's verbatim text, including the double space), exit 1 |
| missing/unreadable file | `reading input file: <path>: <io error>`, exit 1 |
| `--help` / `-h` | Caddy's long text verbatim, usage `caddy-rs fmt [--overwrite] [--diff] [<path>]`, and `-c`, `-w`, `-d` |

The located failure is byte-for-byte Caddy's message body:

```text
<path>:<line>: Caddyfile input is not formatted; Tip: use '--overwrite' to update your Caddyfile in-place instead of previewing it. Consult '--help' for more options
```

`<line>` is computed exactly like `FormattingDifference`: CRLF pairs are normalized to LF for the
comparison and the line counter advances over every equal byte before the first difference.

## Oracle evidence

Pinned oracle: `/root/caddy-rs/.scratch/oracle-eval-2.11.9/caddy` (`v2.11.9`).

`/root/caddy-rs/.scratch/logs/t-cli-005-oracle/differential.py` compares the built caddy-rs binary
against the oracle on 34 fixed edge cases (empty/whitespace/BOM/CRLF, heredocs and escaped
heredocs, quoted/backticked braces, imports before a global options block, invalid UTF-8,
unterminated quotes/backticks, excessive nesting) plus 500 deterministic randomized
Caddyfile-ish inputs. For each it compares plain `fmt`, `fmt --diff`, and the file bytes after
`fmt --overwrite`, and additionally compares `fmt -` stdin behaviour for the fixed cases:
**0 differences** in stdout, exit code, and overwritten file bytes.

The unit test `crates/cli/src/fmt.rs::matches_upstream_formatter_corpus` carries all 34 cases from
upstream `formatter_test.go` verbatim and passes.

## Divergences (no new formatting divergence)

Formatting output, `--diff` bytes, `--overwrite` file bytes, exit codes for documented cases and
the located message body all match. What differs is CLI-wide:

1. **stderr envelope** — Caddy routes the error through its zap logger
   (`{"level":"error","ts":...,"msg":"..."}` when piped; a coloured console form on a TTY);
   caddy-rs prints `caddy-rs: error: <message>`. Covered by DIV-0023.
2. **Usage errors** — Cobra prints `Error: ...` and exits 1; clap prints `error: ...` and exits 2.
   This is deliberate and documented in `docs/CLI.md` ("2 for a usage error") with existing tests,
   so it is not changed by this task; it is called out in the proposed DIV-0023 text below.
3. **Help footer** — Caddy appends `Full documentation is available at:
   https://caddyserver.com/docs/command-line`. caddy-rs has no such footer. Covered by DIV-0023.

Not exercised: a real TTY (coloured zap output), filesystem-level failures after a successful read
(permission denied on overwrite, disk full), races between read and overwrite, and very large files
where the difflib LCS matrix is O(lines²). These do not affect the formatted bytes.

Out of scope: Caddy's `adapt` command appends a formatting warning to its warnings when the input
is not formatted (`adapter.go`). caddy-rs adapt still does not; that is an `adapt` surface, not
`fmt`, and is not changed here.

## Proposed register update

`docs/compatibility/BEHAVIOR-DIVERGENCES.md` — replace the DIV-0023 entry with:

> ## DIV-0023 — CLI output is not byte-identical to Caddy
> - Status: accepted
> - Area: CLI
> - Caddy behaviour: `caddy version`, `list-modules`, `adapt`, `fmt` diagnostics, startup banners and error formatting have specific outputs. Runtime failures exit 1 through Cobra, including usage errors (unknown flag, missing flag value), which print `Error: ...`; command errors are structured zap records (`{"level":"error",...,"msg":"..."}` when stderr is not a terminal).
> - caddy-rs behaviour: Commands follow the same verbs and success/failure conventions, and `fmt`'s formatted output, `--diff` rendering, `--overwrite` file bytes and located `file:line:` message body are byte-identical to Caddy v2.11.9. Text output still differs: errors are printed as `caddy-rs: error: <message>` with no zap envelope, `version --json`/`list-modules --json` are stable caddy-rs shapes, the help footer lacks Caddy's documentation URL, and clap usage errors exit 2 with clap's `error:` text where Cobra exits 1 with `Error: ...`. The usage-error exit code is documented in `docs/CLI.md` and asserted by existing tests.
> - Rationale: Scripts depend on verbs, exit codes and formatted output, not on banners or the error envelope; JSON shapes are documented and stable. Byte-identical CLI diagnostics are a non-goal, and changing the clap usage exit code would alter every existing command's documented contract.
> - Tracking: T-OPS-020 T-CLI-005
> - Test: `caddy-rs/crates/cli/tests/cli.rs` covers verbs, exit codes, JSON contracts and the `fmt_*` cases (formatted output, `--diff`, `--overwrite`, stdin, located message, multiple-input error); `crates/cli/src/fmt.rs` carries the upstream formatter corpus.

## Tests

- `crates/cli/src/fmt.rs` (unit)
  - `matches_upstream_formatter_corpus` — all upstream formatter cases, heredocs and quoting.
  - `formatting_difference_locates_the_first_changed_line` — CRLF normalization + line number.
- `crates/cli/tests/cli.rs` (binary integration)
  - `fmt_formats_and_locates_unformatted_input` — stdout bytes, exit 1, `path:1:` message; clean file exits 0.
  - `fmt_preserves_heredocs_and_quoted_literals` — heredoc/quote literals untouched, exit 0.
  - `fmt_overwrite_rewrites_in_place_and_skips_the_lint` — file bytes, no output, exit 0; `-w` beats `-d`.
  - `fmt_diff_prints_aligned_changes_and_still_fails` — exact `  `/`- `/`+ ` output, exit 1 at line 3; clean diff exits 0.
  - `fmt_reads_stdin_for_dash_and_ignores_overwrite_and_diff` — stdin → stdout, exit 0 for `-`, `-w -`, `-d -`.
  - `fmt_reads_the_config_flag_as_the_path` — `--config`.
  - `fmt_defaults_to_the_caddyfile_in_the_working_directory` — default path + located message.
  - `fmt_rejects_multiple_inputs_like_caddy` — both multi-input forms and Caddy's exact text.
  - `fmt_reports_an_unreadable_file_with_its_path` — `reading input file` naming the path, exit 1.
  - `fmt_help_matches_caddys_usage_and_flags` — long help, usage and `-c`/`-w`/`-d`.
