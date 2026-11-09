# T-CONF-057 compatibility note — `forward_auth` user `handle_response` is merged, not overwritten

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task restores Caddy parity for the adapted JSON and adds no new divergence; the only residual
runtime limitation is already registered as DIV-0099 item (4).

## Defect

`forward_auth_handler` in `crates/config/src/adapter.rs` built the canonical 2xx response handler
and then did `object.insert("handle_response", <canonical>)`, replacing any `handle_response`
entries the user wrote in the `forward_auth` block. Caddy emits **both**: its own 2xx copy handler
first and the user's entries after it. The dropped block meant user `respond`, `log_skip`, `vars`
and other handlers never reached the adapted JSON.

## Caddy source reference

- `external/caddy/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`, `parseCaddyfile`:
  `rpHandler.HandleResponse = []caddyhttp.ResponseHandler{}` at construction, then
  `rpHandler.HandleResponse = append(rpHandler.HandleResponse, goodResponseHandler)` **before**
  `rpHandler.UnmarshalCaddyfile(dispenser)`. The user's `handle_response` segments are collected by
  the reverse_proxy unmarshaler and appended by `FinalizeUnmarshalCaddyfile`.
- `external/caddy/modules/caddyhttp/reverseproxy/caddyfile.go`, `FinalizeUnmarshalCaddyfile`:
  appends each user segment, then moves entries **without** a matcher to the end (stable order
  within the matcher and matcher-less groups).

Exact merge semantics implemented:

1. the canonical entry (`{"match": {"status_code": [2]}, "routes": [vars, header copy...]}`) is
   always first — it has a matcher;
2. the user's entries follow in declaration order, with the adapter's existing
   with-matcher/without-matcher partition preserved, so the result equals Caddy's stable partition
   of `[canonical] + user entries` (`handle_response` with a response matcher before matcher-less
   `handle_response`/`replace_status` entries);
3. `handle_response` is absent only when there is no canonical entry — never, for `forward_auth`.

## Oracle verification (Caddy v2.11.9 h1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE)

Each Caddyfile below was adapted with the real binary
(`.scratch/oracle-eval-2.11.9/caddy adapt --adapter caddyfile --pretty`) and with the fixed
`caddy-rs` build, then the parsed JSON was compared with sorted keys (JSON object key order is not
significant). All cases are identical.

| case | Caddyfile shape | oracle entries | result |
|---|---|---|---|
| canonical only | `uri /auth` + `copy_headers Remote-User` | 1 (canonical) | exact match |
| user block only | `uri /auth` + `handle_response { respond "denied" 401 }` | 2 (canonical, user) | exact match |
| user block matching the canonical | `copy_headers` + `@good status 2xx` + `handle_response @good { respond "user-2xx" 200 }` | 2 (both `status_code: [2]`, canonical first) | exact match |
| user `respond`/`log_skip` | `copy_headers` + `handle_response { log_skip; respond "denied" 401 }` | 2 (canonical, user vars+static_response) | exact match |
| matcher + matcher-less merge | `copy_headers` + `@good` handler + matcher-less `log_skip`/`respond` | 3 (canonical, user `@good`, user matcher-less last) | exact match |

The matcher-less entry ordering matches Caddy: `log_skip`/`respond` appear **after** the 2xx-matching
user entry, and the canonical 2xx entry stays first.

## Tests

- `crates/config/tests/upstream_adapt.rs`
  - `forward_auth_canonical_only_matches_caddy` (new fixture `forward_auth_canonical_only.caddyfiletest`)
  - `forward_auth_preserves_the_user_handle_response_block` (new fixtures
    `forward_auth_user_handle_response.caddyfiletest`,
    `forward_auth_user_handle_response_merged.caddyfiletest`)
  - the existing `all_curated_upstream_fixtures_match_caddy` also covers the three new fixtures.
- `crates/server/tests/http_forward_auth_handle_response.rs` (real listener through the Caddyfile
  adapter):
  - `user_handle_response_runs_for_a_non_2xx_auth_response` — auth service answers 401; the user's
    matcher-less `respond denied 401` runs (upstream body does not leak).
  - `canonical_header_copy_runs_before_the_user_handler_for_a_2xx_auth_response` — auth service
    answers 200 `Remote-User: alice`; the canonical entry copies the header, the chain continues,
    and the downstream `respond` observes `user=alice` (the user's matcher-less 401 handler is
    ordered after the canonical entry and does not shadow it).
  - `log_skip_inside_the_user_handle_response_is_rejected_loudly_by_the_runtime` — adaptation emits
    `{"handler":"vars","log_skip":true}`, and the runtime refuses it with the located DIV-0099
    error instead of silently dropping the handler.

## Divergence status

No new `DIV-NNNN` is required. DIV-0099 item (4) already registers that "non-string `vars` values"
inside `handle_response` are located errors in caddy-rs while Caddy executes them. What changes is
that the adapter no longer hides that limitation: `log_skip` inside a `forward_auth` user
`handle_response` now reaches the adapted JSON and the runtime fails loudly at apply time.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, DIV-0099: no behaviour sentence changes. Append this
test to the `Test:` field (keep the existing entries):

> `crates/server/tests/http_forward_auth_handle_response.rs` (`user_handle_response_runs_for_a_non_2xx_auth_response`, `canonical_header_copy_runs_before_the_user_handler_for_a_2xx_auth_response`, `log_skip_inside_the_user_handle_response_is_rejected_loudly_by_the_runtime`)

Optional `Rationale:` sentence if the Lead wants the newly reachable path named:

> The `forward_auth` expansion appends its canonical 2xx copy handler before the user's own `handle_response` entries and the adapter now preserves them in that order (T-CONF-057); a `log_skip` entry therefore reaches the adapter output and is rejected at apply time by this DIV's non-string `vars` rule instead of being silently dropped.

`docs/compatibility/CADDYFILE.md` row `forward_auth` and the "Authelia forward auth" section are
updated in this branch to describe the merge and the runtime limitation.
