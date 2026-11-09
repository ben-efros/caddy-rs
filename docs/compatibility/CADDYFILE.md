# Caddyfile compatibility

caddy-rs targets Caddy **v2.11.9**. The Caddyfile is an adapter to the native JSON configuration,
exactly as in Caddy: `caddy-rs adapt` lexes, parses, adapts and emits Caddy JSON.

Support is decided **per directive**. A directive that is not supported is rejected with an error
that names it and the line it appears on — it is never silently ignored:

```
caddy-rs: error[config.invalid]: cannot adapt `/etc/caddy/Caddyfile`: invalid configuration at
`Caddyfile line 25`: directive `push` is not supported by this build
```

Check a configuration before running it:

```sh
caddy-rs adapt --config ./Caddyfile --adapter caddyfile --pretty
caddy-rs validate --config ./Caddyfile --adapter caddyfile
```

## Structure supported

| Form | Status | Notes |
|---|---|---|
| Site block with braces `example.com { ... }` | **exact** | One or more addresses on the site line. |
| Single site without braces `:80` followed by directives | **exact** | Only when it is the sole site; ambiguity is rejected. |
| Multiple addresses `example.com, www.example.com { ... }` | **exact** | Comma or whitespace separated. |
| Site addresses `host`, `host:port`, `:port`, `http://`, `https://`, `[::1]:port` | **exact** (subset) | Only `http`/`https` schemes; others are rejected by name. |
| Global options block `{ auto_https off ... }` | **adapted** | `auto_https` (`off`, `disable_redirects`, `ignore_loaded_certs`), `http_port`, `https_port`, `email`, `acme_ca`, `acme_ca_root`, `acme_dns`, `local_certs` and `pki { ca [<id>] { ... } }` are parsed and mapped to `apps.tls`/`apps.pki` JSON (`pki` supports name/root_cn/intermediate_cn/intermediate_lifetime/maintenance_interval/renewal_window_ratio and root/intermediate cert/key/format); `servers [<addr>] { ... }` is adapted for its narrow subset (`listener_wrappers`, the trusted-proxy options and `0rtt off`; see the dedicated row); `debug`, `skip_install_trust`, other `servers` sub-options and unknown options remain loudly rejected. |
| `servers [<addr>] { ... }` | **adapted (narrow subset)** | Emits per-server `listener_wrappers`: `proxy_protocol` (`timeout <Go duration>` → integer ns; `allow`/`deny <CIDRs...>`; `fallback_policy <policy>` with `ignore` omitted and others upper-cased), the `tls` ordering marker and `http_redirect`; the trusted-proxy fields; and `0rtt off`, which emits `"allow_0rtt": false` exactly like real Caddy v2.11.9 (only `off` is accepted). `servers <addr>` applies only to servers whose listen list contains that address; bare `servers` applies to every server; duplicate listener addresses are rejected. All other `servers` sub-options (timeouts, name, keepalive_*, protocols, max_header_size, enable_full_duplex, log_credentials, strict_sni_host, packet_conn_wrappers, metrics) and wrapper arguments stay located errors. |
| Nested directive blocks and named matchers `@name { ... }` | **exact** | One-line named matcher `@name path /x` supported. |
| Comments, quoted strings, backtick raw strings | **exact** |
| Heredocs `<<EOF` | **exact** | Indentation rules, blank lines, CRLF, same-line args, escaped `\<<`, Caddy-compatible diagnostics for bad markers. Evidence: `crates/config/tests/heredoc_env.rs` + upstream `heredoc*` fixtures. |
| Backslash line continuation | **exact** | Trailing `\` suppresses the newline per Caddy's rule. |
| Snippets `(name)` / `import <snippet> [args...]` | **exact (same-file)** | `{args[N]}`, `{args[:]}`, `{block}`, `{blocks.NAME}`, cycle detection, Caddy diagnostics. File/glob imports rejected loudly . |
| `&(named_route) { ... }` / `invoke` | **exact (same-file)** | Definitions parse with duplicate diagnostics; `named_routes` and `invoke` handlers are emitted transitively. Undefined/duplicate invocations fail loudly. Imported-file names are still absent from some error locations ; file/glob imports remain rejected . |
| Environment placeholders `{$ENV}` / `{$ENV:default}` | **exact** (+warning) | Expanded on raw source before lexing; no escape sequence (Caddy parity); missing variables warn, diagnostics-only . |

## Directives supported

| Directive | Syntax supported | Emitted JSON (summary) | Evidence |
|---|---|---|---|
| `respond` | `respond [<matcher>] <body> [<status>]`; `respond [<matcher>] <status>`; `respond [<matcher>]`; `respond [<matcher>] <status> { body "..." }` | `static_response` with `body`, `status_code` |
| `redir` | `redir [<matcher>] <to> [<code>]` | `static_response` with `Location` header and status (default 302) |
| `file_server` | options: `browse [ { sort <fields...> \ | file_limit <n> } ]`, `pass_thru`, `hide <paths...>`, `index <names...>`, `root <path>`, `status <code>`, `disable_canonical_uris`, `precompressed <formats...>` (in block or inline) |
| `root` | `root [<matcher>] <path>` | `vars` with `root` |
| `method` | `method [<matcher>] <METHOD>` | `rewrite` with `method` |
| `reverse_proxy` | `reverse_proxy [<matcher>] <upstream...> { ... }`; upstreams `host:port`, `http://`, `https://`, `unix//path`, `unix+h2c//path`; options `lb_policy`, `lb_retries`, `lb_try_duration`, `lb_try_interval`, `lb_retry_match`, `header_up`, `header_down`, `request_buffers`, `response_buffers`, `transport http`, health options (health_uri/interval/timeout/status/method/headers, max_fails/fail_duration), and `dynamic srv | a |
| `handle` | `handle [<matcher>] { ... }` | `subroute` wrapped in a matched route; shared `group` when multiple handles |
| `handle_path` | `handle_path <prefix> { ... }` | matched route + `subroute` with leading `rewrite strip_path_prefix` |
| `route` | `route { ... }` | `subroute` preserving inner order |
| `header` | `header [<matcher>] <Field> <value>`, `+Field`, `-Field`, `?Field`, simple blocks | `headers` response set/add/delete |
| `encode` | `encode [gzip] [zstd]`, simple block with `minimum_length`, `match { status/header }`, `gzip <level>`, `zstd { disable_checksum }` | `encode` |
| `tls` | **adapted + runtime** | `tls internal` (local CA), `tls <email>`, `tls <cert> <key>`, block options `ca`, `dns <provider>`, `on_demand` (rejected loudly at runtime), `key_type`, and `issuer internal { ca <id>; lifetime <dur>; sign_with_root }` emit Caddy-compatible `apps.tls` JSON (the internal CA ID must exist in `apps.pki`,). Explicit automation now terminates TLS, obtains certificates (ACME HTTP-01/DNS-01/TLS-ALPN-01 or internal CA), redirects HTTP→HTTPS, and renews with hot-swap; default-on auto-HTTPS is not enabled . Evidence: `tls_automation_policies_*`, `tls_conn_policy_consolidate`, `enable_tls_for_catch_all_site`, `acme_dns_configured`. Explicit `issuer acme [<ca>] { ... }` adapts `timeout` to `acme_timeout`, positional CA/`dir`, `email`, `disable_http_challenge`, `disable_tlsalpn_challenge`, `trusted_roots` and `eab` to Caddy's exact JSON; other ACME options stay located errors and `network_proxy` is JSON-only . |
| `log` | **adapted (runtime-backed subset,)** | Site form `log [<name>] { hostnames <hosts...>; no_hostname; output stdout\ |
| `log_level` | **unsupported (runtime gap)** | Located error: the runtime access log does not honor Caddy's per-request `log_level` variable override, so the adapter rejects the directive instead of emitting a config whose behaviour would differ. |
| `log_skip` | `log_skip [<matcher>]` (no arguments, no block) | `{"handler":"vars","log_skip":true}` exactly like Caddy v2.11.9 (there is no `http.handlers.log_skip` module). The runtime suppresses the access-log entry when the final `log_skip` request variable is the boolean `true`; metrics, status and response are unchanged. Evidence: `crates/config/tests/log_skip_adapt.rs`, `crates/server/tests/http_log_skip.rs`. |
| `skip_log` | **deprecated alias** for `log_skip` (same syntax) | Accepts and emits identical JSON in `compatible` mode (the default) and `warn` mode, emitting Caddy's deprecation warning in both; rejected with a located error naming `log_skip` in `strict` mode. Evidence: `crates/config/tests/log_skip_adapt.rs`, `crates/cli/tests/cli.rs`. |
| `map` | **adapted (runtime-backed)** | `map <source> <destinations...> { <input> <outputs...>; default <outputs...> }` emits Caddy's exact `map` handler: literal and `~` regular-expression sources with `${N}` capture outputs, multiple destinations/defaults, and Caddy scalar coercion (quoted stays string, unquoted `-` is null). Sources/destinations may use any placeholder; Caddyfile shorthands are expanded before parsing. |
| `request_body` | `request_body [<matcher>] { max_size <size>; set <body> }` | `request_body` handler with `max_size` (decimal Caddy size units) and experimental `set` body replacement; runtime enforces the limit lazily (413) |
| `try_files` | `try_files [<matcher>] <files...> [<fallback>]` | `rewrite` route with a `file` matcher (`try_files`/`try_policy`/`split_path`); query-carrying file arguments become grouped routes with Caddy's first-match semantics |
| `uri` | `uri strip_prefix <prefix>`, `uri strip_suffix <suffix>`, `uri replace <search> <replace>`, `uri query <key=value...>` (delete/replace/hash; repeated params) | `rewrite` with the corresponding rewrite fields/query filters |
| `bind` | `bind <hosts...>` | server `listen` addresses with the bound host |
| `metrics` (global option) | `metrics { per_host; observe_catchall_hosts; otlp }` | `apps.http.metrics` (Caddy's experimental opt-in). The core model validates the shape; `per_host`/`otlp` are loudly unsupported . The site `metrics` handler directive remains unsupported. |
| `rewrite` | **adapted (runtime-backed)** | `rewrite [<matcher>] <to>` with absolute path, path+query and shorthand placeholders; rewrite routes are emitted in Caddy's mutually exclusive group order |
| `php_fastcgi` | **adapted (runtime-backed)** | Canonical expansion to a 308 directory redirect + `try_files` rewrite + FastCGI `reverse_proxy`; subdirectives `split`/`index`/`try_files`/`root`/`env`/`resolve_root_symlink`/`dial_timeout`/`read_timeout`/`write_timeout`/`capture_stderr`, reverse_proxy passthrough options, response matchers and `handle_response` blocks; the hand-written expanded form (`route` + `file` matchers + `{file_match.relative}`) also adapts |
| `acme_server` | **adapted (runtime pending)** | `acme_server [<matcher>] { ca <id>; lifetime <duration>; resolvers <address...>; challenges <type...>; allow_wildcard_names; allow { domains; ip_ranges }; deny { domains; ip_ranges }; sign_with_root }` emits Caddy's exact `http.handlers.acme_server` JSON (Go durations as integer nanoseconds, `omitempty` fields, `policy` object) and, for `ca`, Caddy's `apps.pki` CA entry when the global `pki` option does not define that ID. All eight upstream `acme_server_*` fixtures adapt identically to the v2.11.9 oracle. The runtime handler  is not implemented yet, so such a config does not load. |
| `templates` | **adapted (subset)** | `templates [<matcher>] { mime <types...>; between <open> <close>; root <path> }` emits Caddy's exact JSON (`mime_types`/`delimiters`/`file_root`, golden-verified); the runtime supports the documented template subset . |
| `rate_limit` | **runtime JSON extension only** | No Caddyfile adapter yet; use the caddy-rs `rate_limit` handler in JSON . |
| `error` | **exact** (subset) | `error [<matcher>] <message> [<status>]` → `error` handler; status may be an integer or a status placeholder, message is a placeholder-expanded string. |
| `handle_errors` | **adapted** | `handle_errors [<codes>] {...}` → server `errors.routes` with status-code filters (integers, classes like `4xx`, ranges) emitted as the canonical `expression` status subset; host wrapping and route ordering follow Caddy (issue #5124). Site-block only; nested use is a located error. |
| `reverse_proxy` `handle_response` forms | **adapted** | `@name status |
| `forward_auth` | **adapted + runtime** | Adapts to Caddy's canonical expansion (`reverse_proxy` + `rewrite` + request header set + `handle_response` header copy) and executes end to end; verified by the local acceptance scenario `forward_auth_authelia` (AS-05). Live Authelia deployment remains external . |
| `basic_auth` | **adapted + runtime** | `basic_auth`/`basicauth` adapt to the `authentication` handler (`bcrypt` hashes, optional realm) and execute; Caddy's broader provider/hash forms are rejected loudly . |

## Matchers supported

| Matcher | Status | Notes |
|---|---|---|
| `host` | **exact** | Wildcards, case/port-insensitive. |
| `path` | **exact** (subset) | `*` wildcards. |
| `method` | **exact** |
| `header` | **adapted** | `*` and `!` negation; regex not yet. |
| `query` | **adapted** | Wildcards on key and value. |
| `file` | **adapted (subset)** | Inline arguments become `try_files`; the block supports `root`, `try_files`, `try_policy`, `split_path`; Caddyfile shorthands expand before parsing. `root`/`try_files` placeholders expand per request with Caddy's `ReplaceAll`/`ReplaceFunc` modes (including the `.` root fallback and glob-safe values); glob patterns, trailing-slash/split semantics, `{http.matchers.file.*}` outputs and `=NNN` fallbacks match Caddy v2.11.9; custom `fs` modules are rejected loudly (/). |
| `path_regexp` | **unsupported at runtime** | Adapts, validates, fails loudly . |
| `not` | **exact** | Negates the enclosed matcher set. |
| `remote_ip`, `client_ip`, `protocol`, `tls` | **adapted** | Adapted to Caddy JSON and validated against the builtin matcher registry (`remote_ip`/`client_ip` CIDR + `private_ranges`, `protocol` schemes/versions, `tls` handshake_complete); unsupported TLS metadata rejected loudly . |
| `expression` | **adapted (subset)** | `@name expression <CEL>` emits Caddy's exact JSON (multi-token bare string with raw-token quoting, single-token object with the matcher name); the runtime supports the documented CEL subset . |
| Inline path matcher (first argument starting `/`) | **exact** | Becomes `{"path": [...]}`. |
| Named matcher reference `@name` | **exact** | Resolved against the site's matcher definitions. |

## Adapter behaviour

- Global options are read before any site block; an unknown option is a located error, as is an
  `admin` block (use `admin off` or `admin <address>`).
- Braced block nesting is bounded at 128 levels; a deeper file fails with a located error instead of
  exhausting the stack.
- Environment placeholders: `{$VAR}` and `{$VAR:default}` are expanded while parsing, `{env.VAR}`
  at request time.
- Snippets and `import` are expanded before adaptation, with arguments substituted.
- Heredocs (`<<EOF`) and line continuations are supported.
- A directive may be supported with a narrower syntax than Caddy accepts. Using the unsupported part
  fails adaptation and names the construct rather than dropping it.
- `--adapt-mode compatible|warn|strict` (caddy-rs extension; default `compatible`) selects the
  configuration-acceptance strictness on `adapt`, `validate` and `run`. It currently gates the
  deprecated-alias table only: `skip_log` → `log_skip` and `basicauth` → `basic_auth` are accepted
  with Caddy's deprecation warning in `compatible` (the default) and `warn`, and rejected with a
  located error naming both spellings in `strict` (where `warn` becomes a superset once more
  ambiguity constructs are gated). `log_skip` itself and every non-alias construct
  are accepted in all modes. The flag never relaxes a security rejection: every other located error
  (unknown module/directive, TLS/auth/trust validation, nesting depth, ...) is unchanged.

## Reference deployment examples

These are the configurations the acceptance scenarios target. Status is explicit; nothing here is
claimed as working until its acceptance task closes.

### Reverse proxy to Jellyfin (supported today)

```caddyfile
jellyfin.example.com {
	reverse_proxy localhost:8096
}
```

Adapts to host+subroute+`reverse_proxy` JSON. Media streaming and WebSocket control are
 /; full acceptance is.

### Multiple virtual hosts with headers (supported subset)

```caddyfile
jellyfin.example.com {
	header {
		Strict-Transport-Security "max-age=31536000"
	}
	reverse_proxy localhost:8096
}

photos.example.com {
	root * /srv/photos
	file_server browse
}
```

### Authelia forward auth

```caddyfile
app.example.com {
	forward_auth authelia:9091 {
		uri /api/verify?rd=https://auth.example.com
		copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
	}
	reverse_proxy app:8080
}
```

Supported: adapts to the canonical `reverse_proxy` + `rewrite` + `handle_response` expansion and
executes end to end (401/403 pass-through, identity header copy on 2xx); local acceptance evidence is
AS-05 (`forward_auth_authelia`). A live Authelia deployment remains externally blocked
.

### Cloudflare DNS-01

```caddyfile
{
	email ops@example.com
}

*.example.com {
	tls {
		dns cloudflare {$CLOUDFLARE_API_TOKEN}
	}
	reverse_proxy localhost:8096
}
```

Supported: `tls`/global ACME options adapt, the Cloudflare DNS-01 provider is constructed from
`challenges.dns.provider` configuration with DNS-over-HTTPS propagation checks, and issuance is
mock-tested end to end (//). **Live staging DNS-01 issuance is
validated** with `tools/acceptance/live_cloudflare_dns01.py` for both a single host and a wildcard
(, 2026-11-04); production/HTTP-01/TLS-ALPN-01 remain credential/host gated.
