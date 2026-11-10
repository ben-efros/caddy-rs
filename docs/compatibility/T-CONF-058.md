# T-CONF-058 compatibility note — `replace_status`/`handle_response` ordering matches Caddy's two phases

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task restores Caddy parity for the adapted JSON and adds no new divergence; it removes the ordering
gap previously noted under DIV-0099.

## Defect

Caddy collects `reverse_proxy` response handlers in two phases:

- `replace_status` is appended to `Handler.HandleResponse` **immediately**, while
  `UnmarshalCaddyfile` walks the block;
- `handle_response` segments are only recorded (`h.handleResponseSegments`) and appended later in
  `FinalizeUnmarshalCaddyfile`, after the whole block has been read.

`FinalizeUnmarshalCaddyfile` then moves entries **without** a response matcher to the end, stably
within each group. Caddy therefore adapts interleaved declarations as "every `replace_status` first,
then every `handle_response`", not in declaration order. caddy-rs collected both in declaration
order, so a matcher-less `replace_status` that overlapped a matcher-less `handle_response` produced
different `handle_response[]` JSON (a different first-match response handler at runtime).

## Caddy source reference

- `external/caddy/modules/caddyhttp/reverseproxy/caddyfile.go`, `UnmarshalCaddyfile`:
  `case "handle_response"` only does
  `h.handleResponseSegments = append(h.handleResponseSegments, d.NewFromNextSegment())`; the
  `case "replace_status"` branch builds the `ResponseHandler` and appends it to `h.HandleResponse`
  directly.
- `external/caddy/modules/caddyhttp/reverseproxy/caddyfile.go`,
  `FinalizeUnmarshalCaddyfile`: loops over `h.handleResponseSegments` and appends the parsed
  subroutes to `h.HandleResponse`, then partitions `h.HandleResponse` into `withMatchers` and
  `withoutMatchers` and assigns `append(withMatchers, withoutMatchers...)`.
- `external/caddy/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`, `parseCaddyfile`:
  seeds `rpHandler.HandleResponse` with the canonical 2xx copy handler **before** calling
  `rpHandler.UnmarshalCaddyfile(dispenser)` and `rpHandler.FinalizeUnmarshalCaddyfile(h)`, so the
  canonical entry is part of the with-matcher group and stays first.

## Ordering rule implemented

`reverse_proxy_handler` in `crates/config/src/adapter.rs` now keeps two collections while walking
the block:

1. `replace_status` entries are pushed to a dedicated `replace_status` vector, in declaration order;
2. `handle_response` entries are pushed to `handle_response`, in declaration order;
3. at finalize the two are concatenated (`replace_status` then `handle_response`) and stably
   partitioned into entries with a `match` and entries without one, with the matcher-less entries
   last.

`forward_auth_handler` prepends the canonical 2xx entry to the already-finalized array, so the
canonical entry stays first and the user's entries keep the same phase order.

## Oracle verification (Caddy v2.11.9 h1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE)

Each Caddyfile below was adapted with the real binary
(`.scratch/oracle-eval-2.11.9/caddy adapt --config <file> --adapter caddyfile --pretty`) and with
the caddy-rs config crate, then the parsed JSON was compared with sorted keys (JSON object key order
is not significant). The "before" column is the unmodified adapter, the "after" column is this
branch.

| case | declaration order | before | after |
|---|---|---|---|
| `interleaved_plain` | `handle_response`, `replace_status 404`, `handle_response`, `replace_status 500` | `[hr first, rs 404, hr second, rs 500]` — **differs from oracle** | `[rs 404, rs 500, hr first, hr second]` — exact match |
| `interleaved_matchers` | `replace_status @s 400`, `handle_response @s`, `replace_status @s 401`, `handle_response @s` | `[rs 400, hr, rs 401, hr]` — **differs from oracle** | `[rs 400, rs 401, hr, hr]` — exact match |
| `interleaved_mixed` | `handle_response @s`, `replace_status 502`, `handle_response`, `replace_status @s 503` | `[hr @s, rs 503, rs 502, hr]` — **differs from oracle** | `[rs 503, hr @s, rs 502, hr]` — exact match |
| `forward_auth_interleaved` | `handle_response`, `replace_status 403`, `handle_response @good` inside `forward_auth` | `[canonical, hr @good, hr denied, rs 403]` — **differs from oracle** | `[canonical, hr @good, rs 403, hr denied]` — exact match |
| `noninterleaved` | all `replace_status` before all `handle_response` | `[rs 400, hr, rs 502, hr]` — matches oracle | identical to before — exact match |

The four interleaved cases failed against the oracle before the change and match it after; the
non-interleaved regression case is byte-identical before and after, and matched the oracle in both
runs. Evidence logs: `.scratch/logs/T-CONF-058/` (Caddyfiles, `.oracle.json`, `.before.json`,
`.caddy-rs.json`, `cargo-test.log`).

## Tests

Golden fixtures (`crates/config/tests/fixtures/local/`), each a `.caddyfile` + exact `.json` pair
exercised by `local_adapt::local_fixtures_have_exact_output_and_validate` (exact adapted JSON plus
`validate_config` against the builtin registry):

- `reverse_proxy_replace_status_interleaved_plain`
- `reverse_proxy_replace_status_interleaved_matchers`
- `reverse_proxy_replace_status_interleaved_mixed`
- `forward_auth_replace_status_interleaved`
- `reverse_proxy_replace_status_noninterleaved` (regression: plain config unchanged)

Named ordering assertions (`crates/config/tests/replace_status_order_adapt.rs`, 5 tests):

- `matcher_less_replace_status_precedes_handle_response_in_both_orders`
- `response_matchers_do_not_break_the_phase_order`
- `matcher_less_entries_move_last_after_the_phase_order`
- `non_interleaved_replace_status_order_is_unchanged`
- `forward_auth_canonical_handler_stays_first_and_phase_order_follows`

`cargo test --offline --locked -p caddy-rs-config`: **340 passed, 0 failed** (5 of them new);
`cargo fmt --all -- --check` clean.

## Divergence status

No new `DIV-NNNN` is required: the interleaving gap was a caddy-rs adapter defect, and the fix
matches Caddy exactly. DIV-0099's `Rationale` should drop the "Known pre-existing ordering gap"
sentence and its `Test` field should gain the new fixtures/tests (exact text below).

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, DIV-0099 `Rationale:` — replace the final sentence

> Known pre-existing ordering gap (not introduced by `T-CONF-057`): `replace_status` is collected in declaration order while Caddy defers `handle_response` to finalize, so interleaved declarations of the two can adapt in a different order; filed as `T-CONF-058`.

with

> Ordering matches Caddy's two-phase collection (`T-CONF-058`): every `replace_status` entry is appended during unmarshal and every `handle_response` block during finalize, so interleaved declarations emit all `replace_status` entries first, then all `handle_response` entries, then a stable matcher-less-last partition.

Append to DIV-0099 `Test:` (keep the existing entries):

> `crates/config/tests/replace_status_order_adapt.rs` (`matcher_less_replace_status_precedes_handle_response_in_both_orders`, `response_matchers_do_not_break_the_phase_order`, `matcher_less_entries_move_last_after_the_phase_order`, `non_interleaved_replace_status_order_is_unchanged`, `forward_auth_canonical_handler_stays_first_and_phase_order_follows`), golden local fixtures `reverse_proxy_replace_status_interleaved_{plain,matchers,mixed}`, `reverse_proxy_replace_status_noninterleaved`, `forward_auth_replace_status_interleaved` (exact output + validation via `local_fixtures_have_exact_output_and_validate`) — `T-CONF-058`.

`docs/compatibility/CADDYFILE.md`, row `reverse_proxy` `handle_response` forms — replace with
(this also escapes the `|` characters that currently truncate the row in Markdown tables):

> | `reverse_proxy` `handle_response` forms | **adapted** | `@name status\|header ...`, `handle_response [@name] {...}`, `replace_status [@name] <status>`, `copy_response [<status>]`, `copy_response_headers {include\|exclude ...}` adapt to Caddy's `handle_response[]` JSON and run end to end (status/header matching, pass-through, `replace_status`, synthetic responses, copy body/headers; body buffered on copy, `DIV-0099`). Ordering matches Caddy's two-phase collection: every `replace_status` (in declaration order) precedes every `handle_response` (in declaration order), then entries without a response matcher move last, stably (`T-CONF-058`). |

`docs/compatibility/CADDYFILE.md`, `forward_auth` section — append after the sentence ending
"response reaches the user's handler":

> Interleaved `replace_status`/`handle_response` declarations keep Caddy's two-phase order: every
> `replace_status` entry first (in declaration order), then the deferred `handle_response` blocks (in
> declaration order), then matcher-less entries last, stably (`T-CONF-058`).

`ADAPT-CONFORMANCE.md` is unaffected: none of the upstream `caddyfile_adapt` fixtures that contain
`replace_status` (`reverse_proxy_handle_response`, `intercept_response`) interleaves the two
directives, and `intercept` is not adapted by this build.
