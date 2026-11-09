# T-ADMIN-049 compatibility note — access-log filters and the shared replacement engine

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. DIV-0015
currently describes only the routing `path_regexp` matcher/rewrite. This note extends the entry's
scope to the admin access-log `regexp`/`multi_regexp` filters, which delegate to the same shared
`caddy-rs-core` regex wrapper and therefore share its replacement expansion (Go-compatible for well-formed ASCII references). The exact
sentence for the Lead to merge is at the bottom.

## Oracle verification (Go 1.26.4)

`regexp_replace_all` in `crates/admin/src/access_log.rs` calls
`caddy_rs_core::regex::Regex::replace_all`, so the Go oracle is
`regexp.MustCompile(pattern).ReplaceAllString(input, replacement)`. Every case below was run through
that oracle (`go version go1.26.4-X:nodwarf5 linux/amd64`); the expected strings in the new tests
are the oracle outputs, not samples from the Rust engine.

| area | pattern | replacement | input | Go result | caddy-rs |
|---|---|---|---|---|---|
| named `$name` | `(?P<user>[a-z]+)` | `$user` | `alice` | `alice` | equal |
| named `${name}` | `(?P<user>[a-z]+)` | `${user}` | `alice` | `alice` | equal |
| named, two groups | `(?P<user>[a-z]+)@(?P<host>[a-z.]+)` | `$host/$user` | `alice@example.com bob@test.io` | `example.com/alice test.io/bob` | equal |
| non-participating group | `(?P<a>foo)\|(?P<b>bar)` | `[$a\|$b]` | `foo bar` | `[foo\|] [\|bar]` | equal |
| longest unbraced name | `(?P<user>[a-z]+)` | `$userX` | `alice` | `` (group `userX` absent) | equal |
| brace disambiguation | `(?P<user>[a-z]+)` | `${user}X` | `alice` | `aliceX` | equal |
| literal `$` | `(?P<x>a)` | `$$$x` | `a` | `$a` | equal |
| word boundary | `\bfoo\b` | `X` | `foo foe foo_bar barfoo foo` | `X foe foo_bar barfoo X` | equal |
| boundary + named | `\b(?P<num>\d+)\b` | `[${num}]` | `a 12 b 345` | `a [12] b [345]` | equal |
| bare boundary | `\b` | `\|` | `ab cd` | `\|ab\| \|cd\|` | equal |
| non-boundary | `\B` | `\|` | `ab cd` | `a\|b c\|d` | equal |
| mixed numeric+named | `^(?P<user>[a-z]+)/(\d+)/(?P<rest>.*)$` | `${2}-$user-${rest}-$1` | `alice/42/x/y` | `42-alice-x/y-alice` | equal |
| mixed reorder | `(?P<first>\w+)\s+(?P<last>\w+)` | `$2, $1` | `Ada Lovelace` | `Lovelace, Ada` | equal |

No implementation change was required: all named-capture, word-boundary (on ASCII input) and
mixed-expansion cases already match Go.

### Known residual (already registered in DIV-0015)

Go's `\b`/`\B` are ASCII word boundaries (`[0-9A-Za-z_]`), while the Rust `regex` crate's default
`\b` is Unicode-aware. The divergence is only observable with non-ASCII input: for
`\bfoo\b` / `X` / `éfooé`, Go returns `éXé` and the shared wrapper returns `éfooé`. This is the
pre-existing DIV-0015 residual for `\b`/`\w`/`\d`/`\s` (the wrapper deliberately keeps Unicode mode
so scalar `.` and common `.*` patterns work on `&str`), not a T-ADMIN-049 regression. The new tests
use ASCII inputs, where both engines agree, and do not claim compatibility for the residual.

## Tests added

`crates/admin/src/access_log.rs`:

- `regexp_filter_named_captures_match_go` — `$name`, `${name}`, multiple named groups,
  non-participating and absent groups, longest-parse `$name`, brace disambiguation and `$$`.
- `regexp_filter_word_boundaries_match_go` — `\b`, `\B`, boundary-anchored named captures and
  underscore word-character behavior.
- `regexp_filter_mixed_numeric_and_named_expansion_matches_go` — `$N`, `${N}`, `$name` and
  `${name}` addressing the same and different groups in one template.
- `regexp_and_multi_regexp_filters_apply_named_captures_and_word_boundaries` — the end-to-end
  `AccessLogEntry::render` path through both `regexp` and `multi_regexp` filters.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, DIV-0015 (`caddy-rs behaviour`): append this exact
sentence to the end of the paragraph:

> The admin access-log `regexp` and `multi_regexp` filters use the same shared `caddy-rs-core` regex wrapper, with Go-compatible replacement expansion for **well-formed** references (`$N`/`${N}`/`$name`/`${name}`, non-participating or absent groups expanding to nothing, and longest-parse unbraced names); malformed references diverge from Go's `Regexp.ReplaceAllString` (for pattern `(a)` and input `a`: Go expands `$01`/`${01}`/`$<2-digit-char>` to the empty string and leaves `${}`/`${a b}` literally, where caddy-rs expands `$01`/`${01}` to the first group, drops `${}`/`${a b}`, and leaves `$\u{e9}` literal — registered as a DIV-0015 residual and covered by `regexp_filter_malformed_reference_parsing_diverges_from_go`); the Unicode `\b`/`\w`/`\d`/`\s` residual above applies to filter patterns too.

Recommended companion edits (optional, but they keep the entry auditable):

- `Tracking:` append ` T-ADMIN-049`.
- `Test:` append
  `` `crates/admin/src/access_log.rs` (`regexp_filter_named_captures_match_go`, `regexp_filter_word_boundaries_match_go`, `regexp_filter_mixed_numeric_and_named_expansion_matches_go`, `regexp_and_multi_regexp_filters_apply_named_captures_and_word_boundaries`) ``.
- `Area:` may become `Routing / Logging` if the Lead wants the expanded scope visible in the index;
  no other DIV-0015 field changes (status stays `fixed`).

No `CONFIGURATION.md` or `CADDYFILE.md` row changes are required: access-log field filters are JSON
configuration and this task changes no accepted configuration or emitted JSON.

### Reference-parsing residuals (verified against Go 1.26.4)

For pattern `(a)` and input `a`, Go's `Regexp.ReplaceAllString` and caddy-rs disagree on
malformed references. "Well-formed" means ASCII `$N`/`${N}`/`$name`/`${name}` references; Go
also accepts Unicode letters in a reference name, which is one of the divergences below.

| template | Go | caddy-rs |
|---|---|---|
| `$01` | `` (empty) | `a` |
| `${01}` | `` (empty) | `a` |
| `${}` | `${}` | `` (empty) |
| `${a b}` | `${a b}` | `` (empty) |
| `$é` | `` (empty) | `$é` |

These are registered as part of the DIV-0015 reference-parsing residual and asserted by
`regexp_filter_malformed_reference_parsing` (caddy-rs side).
