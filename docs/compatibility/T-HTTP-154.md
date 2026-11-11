# T-HTTP-154 compatibility note — HSTS preload support in `security_headers`

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
task extends the caddy-rs `security_headers` middleware (T-HTTP-150) with HSTS preload support:
preload-list admission warnings, an HTTPS-only emission gate in the handler, and an RFC 6797
header value. The note below states only behaviour this implementation can point at a test for;
the proposed register entry is at the end.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

- There is **no Caddy equivalent** of this module. Caddy v2.11.9 only ships the generic `headers`
  handler (`modules/caddyhttp/headers/headers.go`), which stages exactly the response headers the
  user configures. It has no HSTS-specific configuration, no `max-age`/`includeSubDomains`/`preload`
  validation, no preload-list checks or warnings, and no TLS-aware staging of
  `Strict-Transport-Security`; a user must spell the header out by hand and is responsible for
  emitting it only over HTTPS.
- RFC 6797 §6.1 — the `Strict-Transport-Security` value is `max-age=<seconds>` followed by the
  optional `; includeSubDomains` and `; preload` directives, in that order. The preload-list
  admission requirements are operated by <https://hstspreload.org>: at least one year
  (`max-age=31536000` or greater), `includeSubDomains`, and an accepted domain submission.

## Implemented behaviour

| Configuration / transport | Behaviour |
|---|---|
| `SecurityHeaders` run as a `Handler` over TLS (`Request::tls == true`) | stages `Strict-Transport-Security` plus the other configured headers |
| the same over plain HTTP (`Request::tls == false`) | stages no `Strict-Transport-Security`; the non-HSTS headers are still staged |
| `max_age`, `include_subdomains`, `preload` | all configurable; the value is `max-age=<max_age>[; includeSubDomains][; preload]` |
| `SecurityHeaders::apply(&mut HeaderMap)` | unconditional form: never inspects a request, so it stages HSTS whenever configured; used by the route engine (T-HTTP-152) which owns the HTTPS condition |
| `max_age == 0`, `max_age < 15552000` (180 days), `preload` without `include_subdomains` | `validate()` returns a located `InvalidConfig` error, unchanged from T-HTTP-150 |
| `preload` with `max_age < 31536000` | `SecurityHeadersConfig::warnings()` reports the required one-year (`31536000`) minimum and the configured value; configuration stays valid |
| `preload` enabled | `warnings()` always reports that preload-list membership cannot be verified or looked up at config time |
| `preload` disabled | `warnings()` is empty |

`HSTS_PRELOAD_MIN_MAX_AGE` (`31536000`) is public alongside the existing `HSTS_MIN_MAX_AGE`
(180 days) so callers and tests do not repeat the number.

Tests: `crates/http/src/security_headers.rs`
`hsts_is_staged_on_https_responses_only`,
`hsts_directives_are_configurable`,
`hsts_header_value_matches_rfc_6797`,
`preload_below_one_year_warns_with_required_and_configured_max_age`,
`preload_membership_cannot_be_verified_at_config_time`,
`no_preload_warnings_when_preload_is_disabled`,
`apply_stages_hsts_unconditionally_for_route_engines`, plus the unchanged T-HTTP-150 tests
(`hsts_is_opt_in_and_requires_valid_config`, `stages_headers_on_response_without_mutating_body`,
…).

## Residual divergences

1. This is a caddy-rs extension with no Caddy v2.11.9 equivalent. Upstream users of the `headers`
   handler get no validation, no preload warnings and no transport-aware staging for this header;
   caddy-rs accepts a structured `HstsConfig` and enforces those rules.
2. Preload-list membership cannot be looked up at config time (the check is an online submission
   at `https://hstspreload.org`). It is an always-on warning rather than a hard error so a
   configuration that is otherwise valid can still start offline.
3. `preload` without `includeSubDomains` is a located hard error, where the upstream generic
   `headers` handler would emit whatever value the user wrote (which the preload list would
   reject).
4. Warnings are plain strings returned by a public method, not Caddy JSON zap log records; the
   caller (config adapter / server startup) decides how to surface them.
5. The `Handler` implementation is the HTTPS gate. Callers that use `apply` directly are
   responsible for staging the header only on HTTPS responses; that is the intended contract for
   the route engine (T-HTTP-152), which performs the transport check itself.

## Proposed register entry (program repository)

```text
## DIV-0120 — `security_headers` adds HSTS preload validation and HTTPS-only emission

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no HSTS-specific handler. The generic `headers` handler
  (`modules/caddyhttp/headers/headers.go`) stages the `Strict-Transport-Security` value the user
  spells out, on every response the route matches, with no validation of `max-age`,
  `includeSubDomains` or `preload`, no preload-list admission checks or warnings, and no
  transport-aware gating.
- caddy-rs behaviour: `security_headers` accepts a structured `HstsConfig { max_age,
  include_subdomains, preload }`. The `Handler` implementation stages
  `Strict-Transport-Security` only when `Request::tls` is true; plain-HTTP responses get no HSTS
  header even when configured. `SecurityHeaders::apply(&mut HeaderMap)` remains the unconditional
  form for route-engine callers that own the HTTPS condition. The value follows RFC 6797
  (`max-age=<seconds>[; includeSubDomains][; preload]`). `validate()` hard-rejects
  `max_age == 0`, `max_age < HSTS_MIN_MAX_AGE` (15552000), `preload` without `include_subdomains`,
  and invalid header values. `SecurityHeadersConfig::warnings()` reports — without failing — a
  preload `max_age` below `HSTS_PRELOAD_MIN_MAX_AGE` (31536000), naming the required minimum and
  the configured value, and the fact that preload-list membership cannot be verified or looked up
  at config time.
- Rationale: the preload directive is a long-lived commitment that browsers and the preload list
  validate; failing silently or emitting HSTS over cleartext would be a defect. The measurable
  requirements are enforced, and the unverifiable online requirement is surfaced as a warning so
  offline configuration still works.
- Status: extension (no upstream equivalent); divergent where it validates/warns
- Tracking: T-HTTP-154
- Test: `crates/http/src/security_headers.rs` `hsts_is_staged_on_https_responses_only`,
  `hsts_header_value_matches_rfc_6797`,
  `preload_below_one_year_warns_with_required_and_configured_max_age`,
  `preload_membership_cannot_be_verified_at_config_time`,
  `hsts_directives_are_configurable`
```
