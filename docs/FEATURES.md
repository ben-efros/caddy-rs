# Features

caddy-rs is an HTTP server that speaks Caddy's configuration model: it accepts Caddyfiles through
an adapter or native JSON, and runs the resulting servers from a single process. This page
describes the behaviour this build implements, organised by area. For how to write and load
configuration, see [CONFIGURATION.md](CONFIGURATION.md).

## HTTP server

Each entry under `apps.http.servers` is an independent server with its own listeners, routes and
TLS connection policies. A server listens on one or more addresses of the form `:443`,
`127.0.0.1:8080`, `[::1]:8443` or `unix//run/caddy.sock`; `udp/...` addresses are QUIC listeners.

| Capability | Behaviour |
|---|---|
| HTTP/1.1 | Served on every listener, including cleartext and Unix sockets. |
| HTTP/2 over TLS | Negotiated through ALPN (`h2`) when the listener terminates TLS. HTTP/2 settings follow Caddy/Go defaults: 250 concurrent streams, 1 MiB frame and window sizes, and a header-list limit derived from `max_header_bytes`. |
| h2c, prior knowledge | A cleartext listener accepts an HTTP/2 connection that starts directly with the HTTP/2 preface. |
| h2c, upgrade | Add `h2c` to the server's `protocols` to also accept an HTTP/1.1 `Upgrade: h2c` handshake. The server answers `101 Switching Protocols` and continues on HTTP/2. Without that token, the `Upgrade` offer is ignored. |
| HTTP/3 | Served over QUIC with TLS 1.3 and the `h3` ALPN token. A UDP listener is derived automatically for every TLS TCP listen address (an explicit `udp/...` address is used as-is and not duplicated). HTTP/3 is on by default; include `h3` in `protocols` to keep it when you set an explicit list. |
| Alt-Svc | HTTP/1.1 and HTTP/2 responses on a server that offers HTTP/3 carry `Alt-Svc: h3=":<port>"; ma=2592000`, where `<port>` is the first concrete UDP listener port. HTTP/3 responses do not advertise Alt-Svc. A UDP listener on port `0` (ephemeral) is not advertised. |
| Request streaming | Request bodies are handed to the router as a stream. A handler that needs to replay the body (`reverse_proxy` with retries, `try_duration` or `handle_response`, and FastCGI) buffers it once before dispatch. |
| Response streaming | Handlers that can stream — notably `reverse_proxy` — write the response body to the client as it arrives. An exact `Content-Length` is preserved; otherwise the connection frames the body. |
| Protocol upgrades | An HTTP/1.1 `101 Switching Protocols` upgrade is carried through `reverse_proxy` as a bidirectional tunnel, which is how WebSockets are proxied. |
| Extended CONNECT | HTTP/2 extended CONNECT for WebSocket (`:protocol: websocket`, RFC 8441) is accepted and proxied when the process runs with `GODEBUG=http2xconnect=1`, matching Go's default-off gate. Without that variable the server does not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and answers such requests with `501`. |
| Graceful shutdown | The first `SIGINT`/`SIGTERM` starts a graceful shutdown. `apps.http.shutdown_delay` keeps listeners serving for a configured interval first; `apps.http.grace_period` then bounds the wait for in-flight requests. A second signal closes connections immediately. |

Per-server limits and timeouts are available as `read_timeout`, `write_timeout`, `idle_timeout`,
`read_header_timeout` and `max_header_bytes`. Two additional fields are this build's hardening
extensions: `max_request_body_size` (bytes, `0` means unlimited) and `max_connections` (concurrent
connections per listener, `0` means unlimited).

Server-level `trusted_proxies`, `trusted_proxies_strict`, `trusted_proxies_unix` and
`client_ip_headers` control how the proxy's forwarding headers are believed. They affect the
resolved client address used by the `client_ip` matcher, forwarding decisions and access logs.

## Routing

A server owns an ordered list of routes. Each route has a list of matcher sets, a handler chain,
and optional `terminal` and `group` fields.

- **Matching**: a route matches when any matcher set matches (OR), and a matcher set matches when
  every matcher in it matches (AND). An empty `match` matches everything.
- **Handlers**: the route's `handle` chain runs in order. A handler can respond, continue to the
  next handler, or start a protocol tunnel.
- **Terminal**: `terminal: true` stops route evaluation once the route matches, even if its
  handlers did not respond.
- **Groups**: routes in the same `group` are mutually exclusive; only the first matching route in
  a group runs.
- **Subroutes**: the `subroute` handler runs a nested route list with the outer handler chain as
  its continuation, so an empty or non-matching subroute behaves as a no-op.
- **Error routes**: `apps.http.servers.<name>.errors.routes` runs when a handler returns an error
  or produces an error status. In error mode a terminal route or an unhandled fall-through
  produces the original status with an empty body.
- **Route identity**: a route can carry `"@id": "name"`. IDs are unique within a configuration and
  addressable through the admin API at `/id/<name>`, including routes nested in subroutes.

```json
{
  "match": [{ "host": ["example.com"], "path": ["/api/*"] }],
  "handle": [
    { "handler": "vars", "upstream": "api" },
    { "handler": "reverse_proxy", "upstreams": [{ "dial": "10.0.0.10:8080" }] }
  ],
  "terminal": true
}
```

The Caddyfile adapter builds the same structures: `route` creates a route evaluated in place,
`handle` creates sibling blocks that are mutually exclusive within the site, and `handle_path` adds
a `strip_path_prefix` rewrite before the block.

## Matchers

Matchers are combined inside a matcher set. The `not` key wraps a list of matcher sets and negates
the whole combination.

| Matcher | JSON configuration | Behaviour |
|---|---|---|
| `host` | array of host patterns | Case-insensitive, port-insensitive match. `*` matches any run of characters. Placeholders are expanded before matching. |
| `path` | array of path patterns | Case-sensitive match against the percent-decoded, cleaned request path. `*` and `?` wildcards. |
| `path_regexp` | `{"pattern": "...", "name": "..."}` | RE2-subset regular expression match on the cleaned path. A successful match publishes `{http.regexp.<index>}` for every capture group and, when `name` is set, `{http.regexp.<name>.<index>}`. Look-around, lazy quantifiers and named capture groups are rejected at load. |
| `method` | string or array of methods | Exact method match; configured values are upper-cased. |
| `header` | object of field → string or array | Every configured field must match one of its values. `*` tests presence, `!value` negates, and other values support `*`/`?` wildcards. |
| `query` | object of key → string or array | At least one query parameter must match each key/value pair. `*`/`?` wildcards apply to both key and value. |
| `file` | `{"root", "try_files", "try_policy", "split_path"}` | Tests candidate files under `root` (default `{http.vars.root}`). `try_policy` is `first_exist` (default), `first_exist_fallback`, `smallest_size`, `largest_size` or `most_recently_modified`. On a match it publishes `{http.matchers.file.relative}`, `.absolute`, `.type` and `.remainder`. In `first_exist`/`first_exist_fallback`, a candidate written `=404` responds with that status. |
| `remote_ip` | `{"ranges": [...]}` | Matches the direct peer address against IPs and CIDR ranges. `private_ranges` expands to the built-in private list. |
| `client_ip` | `{"ranges": [...]}` | Matches the resolved client address, honouring the server's trusted-proxy policy; falls back to the peer address when no proxy is trusted. |
| `local_ip` | `{"ranges": [...]}` | Matches the connection's local (listener) address. This is a caddy-rs extension; the ranges use the same syntax as `remote_ip`. |
| `protocol` | string | `http`, `https`, `grpc`, or an HTTP version: `http/1.0`, `http/1.1`, `http/2`, `http/3`. A trailing `+` means "this version or later" (for example `http/2+`). |
| `tls` | `{"handshake_complete": bool}` | Matches TLS connections. `handshake_complete: false` never matches because this build serves TLS only after the handshake completes. |
| `expression` | `{"expr": "..."}` | A CEL subset: booleans, `!`, `&&`, `||`, parentheses, string and integer literals, comparisons, and `in` over list literals. Caddy placeholders and aliases such as `request.method`, `request.path`, `request.header("X")`, `vars.name` and `tls.enabled` resolve at request time. Unknown identifiers and non-boolean top-level expressions are located configuration errors. |

In Caddyfiles the matcher set appears before the block (`@name` definitions and inline matchers),
and the adapter emits the same JSON matcher objects.

## Handlers

| Handler | Caddyfile directive | Configuration | Behaviour |
|---|---|---|---|
| `static_response` | `respond` | `status_code`, `body`, `headers` | Writes a fixed response, expanding placeholders in the body and header values. A body that is valid JSON gets `application/json`; any other non-empty body gets `text/plain; charset=utf-8`, unless you set `Content-Type`. |
| `file_server` | `file_server` | see below | Serves files from `root`. |
| `headers` | `header` | `request.set`, `response.set/add/delete` | Stages request-header mutations and response-header mutations. `set` replaces all values, `add` appends, `delete` removes. |
| `rewrite` | `rewrite`, `uri`, `method`, `try_files` | `method`, `uri`, `strip_path_prefix`, `strip_path_suffix`, `uri_substring`, `path_regexp`, `query` | Rewrites the request in Caddy's order: method, URI, prefix strip, suffix strip, substring replacements, regexp replacements, then query operations (`rename`, `set`, `add`, `replace`, `delete`). |
| `vars` | `vars` | any string, number or boolean field | Sets request variables consumed by later handlers and by `{http.vars.NAME}` placeholders. |
| `map` | `map` | `source`, `destinations`, `mappings` (`input`/`input_regexp`, `outputs`), `defaults` | Maps a source value to destination placeholders. Mappings are evaluated per destination in order; a matching non-null output wins, otherwise the positional default applies. |
| `templates` | `templates` | `file_root`, `mime_types`, `delimiters` | Executes buffered response bodies whose content type matches `mime_types` (default `text/html`, `text/plain`, `text/markdown`) as templates. Supports `if`/`else`, `range`, `with`, `define`/`template`, variables, pipelines, field access, and functions including `placeholder`/`ph`, `env`, `include`, `import`, `readFile`, `fileExists`, `html`, `upper`, `lower`, `replace`, `split`, `join`, `truncate` and `stripHTML`. File access is confined to `file_root`. |
| `request_body` | `request_body` | `max_size`, `set` | `max_size` bounds how many bytes later handlers may read (exceeding it is `413`); `set` replaces the body with a string and updates `Content-Length`. |
| `encode` | `encode` | `encodings`, `prefer`, `minimum_length`, `match` | Compresses responses with gzip and zstd. See below. |
| `authentication` / `basic_auth` | `basic_auth`, `basicauth` | `providers.http_basic` (`accounts`, `hash`, `realm`) | HTTP Basic authentication. See below. |
| `forward_auth` | `forward_auth` | `upstreams`, `uri`, `method`, `copy_headers`, `header_up`, `trusted_proxies` | Sends a subrequest to an auth service. A `2xx` response copies the configured headers onto the original request and continues; any other status is passed to the client unchanged. |
| `reverse_proxy` | `reverse_proxy`, `php_fastcgi` | see [Reverse proxy](#reverse-proxy) | Proxies requests to configured or discovered upstreams. |
| `subroute` | emitted by `handle`/`route` | `routes` | Runs a nested route list with the outer chain as its continuation. |
| `error` | `error` | `status_code`, `error` | Aborts the handler chain and hands the status and message to the server's error routes. |
| `rate_limit` | — (JSON only) | see below | Token-bucket rate limiting. This is a caddy-rs extension; Caddy has no built-in rate-limit handler. |

### `file_server`

`file_server` serves files under `root`, which defaults to `{http.vars.root}` (set by the `root`
directive or a `vars` handler). It supports:

- **Hide rules**: `hide` lists glob patterns; it defaults to `./Caddyfile`.
- **Index files**: `index_names` defaults to `index.html` and `index.txt`.
- **Directory listings**: `browse: true` renders an HTML listing instead of returning `404`.
- **Pass-through**: `pass_thru: true` continues the handler chain when no file matches.
- **Status override**: `status_code` sets a fixed status or a placeholder string to expand.
- **Canonical URIs**: `canonical_uris: true` (the default) redirects directory requests without a
  trailing slash.
- **Precompressed sidecars**: `precompressed` accepts `gzip`, `br` and `zstd`; the server serves
  `file.gz`, `file.br` or `file.zst` when the client accepts that encoding. `precompressed_order`
  breaks ties between equally acceptable encodings.
- **ETags**: a strong ETag is derived from the file; `etag_file_extensions` reads it from a
  sidecar instead (for example `etag_file_extensions: [".etag"]`).

Representation transfer follows `ServeContent` semantics: `Vary: Accept-Encoding`, `ETag` and
`Last-Modified`, conditional requests (`If-Match`, `If-None-Match`, `If-Modified-Since`,
`If-Unmodified-Since`, `If-Range`), single and multipart byte ranges, `206`/`304`/`412`/`416`
responses, `HEAD`, and `Accept-Ranges: bytes`.

### `encode`

`encode` negotiates `Accept-Encoding` with q-values and a `prefer` tie-break. Enabled encoders are
`gzip` (default level 5) and `zstd` (default speed). `minimum_length` defaults to 512 bytes, and
`match` accepts a status-code list and header matchers for which responses are eligible. The
middleware sets `Content-Encoding` and `Vary: Accept-Encoding`, removes `Content-Length` and
`Accept-Ranges`, suffixes strong ETags with the encoding name, and skips WebSocket handshakes,
`Cache-Control: no-transform` responses, and responses that already have a content encoding.
Streaming responses are compressed chunk by chunk rather than buffered.

### Authentication

`authentication` provides HTTP Basic authentication through the `http_basic` provider. Accounts
list a `username` and a `password` that is a password hash. Supported hash algorithms are `bcrypt`
(`$2a$`, `$2b$`, `$2x$`, `$2y$`) and `argon2id` (PHC strings), with bcrypt as the default. A
`plaintext` algorithm is available as an explicit development extension. On success the handler
sets `{http.auth.user.id}` to the username and continues; on failure it returns `401` with a
`WWW-Authenticate: Basic realm="..."` challenge.

### Template functions

The `templates` handler renders with the delimiters `{{` and `}}` by default, configurable through
`delimiters`. Templates can read request data (`.Req.Method`, `.Req.URL.Path`, `.Req.Header.Get`,
`.Cookie`, `.Host`, `.Args`), set response headers through `.RespHeader.Set/Add/Del`, and call the
functions listed in the handler table. `include`, `import`, `readFile` and `fileExists` resolve
paths under `file_root` and clamp `..` at that root.

### Rate limiting

`rate_limit` is a token-bucket limiter implemented as a caddy-rs extension:

```json
{
  "handler": "rate_limit",
  "rate": "10r/s",
  "burst": 20,
  "key": "{http.request.remote.host}",
  "max_keys": 100000,
  "status_code": 429,
  "headers": { "X-RateLimit-Realm": ["default"] },
  "body": "rate limit exceeded"
}
```

`rate` is required and uses `<count>/<duration>` (for example `10r/s`, `60/m`, `2r/500ms`).
`burst` defaults to the ceiling of the rate, clamped to at least 1. `key` selects the bucket and
defaults to `{http.request.remote.host}`; an empty value uses one shared `"<unknown>"` bucket.
`max_keys` bounds memory by evicting fully refilled buckets oldest-first. Limited responses carry
`Retry-After` and the configured status (default `429`), headers and body. Allowed requests
continue down the handler chain, so place the handler before the ones it protects.

## Reverse proxy

`reverse_proxy` sends requests to one or more upstreams. An upstream dial is `host:port`,
`unix//path`, or a placeholder that expands per request. Per-upstream `max_requests` caps how many
requests may run against that upstream at once.

### Load balancing

Set `load_balancing.selection_policy` to choose a policy. The default is `random`.

| Policy | Configuration | Selection |
|---|---|---|
| `first` | `{"policy": "first"}` | First healthy upstream in configuration order. |
| `round_robin` | `{"policy": "round_robin"}` | Rotates through healthy upstreams. |
| `least_conn` | `{"policy": "least_conn"}` | Upstream with the fewest active requests. |
| `random` | `{"policy": "random"}` | Uniformly random healthy upstream. |
| `random_choose` | `{"policy": "random_choose", "choose": 2}` | Chooses a random sub-pool (at least 2), then the least-loaded member. |
| `weighted_round_robin` | `{"policy": "weighted_round_robin", "weights": [3, 1]}` | Weighted rotation. |
| `cookie` | `{"policy": "cookie", "name": "lb", "secret": "...", "max_age": 0, "fallback": "random"}` | Sticky sessions: the cookie value is an HMAC of the selected dial address. A missing or stale cookie falls back to the fallback policy and re-pins the client with `Set-Cookie`. |
| `ip_hash` | `{"policy": "ip_hash"}` | Hashes the peer IP. |
| `client_ip_hash` | `{"policy": "client_ip_hash"}` | Hashes the resolved client IP. |
| `uri_hash` | `{"policy": "uri_hash"}` | Hashes the request URI. |
| `header` | `{"policy": "header", "field": "X-Session"}` | Hashes a request header value. |
| `query` | `{"policy": "query", "key": "user"}` | Hashes a query parameter value. |

Hash policies fall back to a random healthy upstream when the hash key is absent.

### Retries

`load_balancing.retries` sets how many times a failed request is retried against another upstream
(`0` disables retries). `try_duration` keeps trying for a time window and `try_interval` sets the
pause between attempts. `retry_match` restricts retries to matching requests. A handler that may
retry buffers the request body once so it can be replayed.

### Health checks

- **Active** (`health_checks.active`): periodic probes with `uri` (or the deprecated `path`),
  `method`, `headers`, `body`, `interval`, `timeout`, `passes`, `fails`, `expect_status`,
  `expect_body` and `max_size`. An upstream flips state only after the configured number of
  consecutive passes or failures.
- **Passive** (`health_checks.passive`): observes real requests. `fail_duration` remembers a
  failure (transport error, `unhealthy_status`, or latency at or above `unhealthy_latency`);
  `max_fails` sets the threshold at which the upstream is skipped until the failure ages out.
  `unhealthy_request_count` caps simultaneous requests.

### Dynamic upstreams

`dynamic_upstreams` replaces the static pool with discovered addresses (and falls back to
`upstreams` when a lookup fails):

- `srv`: RFC 2782 SRV lookups, with `service`, `proto`, `name`, `refresh`, `grace_period`, and
  optional `resolver` and `dial_network`.
- `a`: A/AAAA lookups of `name`, dialled on `port` (default 80), with `versions`
  (`{"ipv4": bool, "ipv6": bool}`) filtering the address family.
- `multi`: queries each listed source and concatenates the results.

### Upstream TLS

Put a `tls` object in `transport` to connect with TLS:

| Field | Behaviour |
|---|---|
| `root_ca_pem_files`, `root_ca_pool` | Replace the system trust store with the given roots. |
| `ca` | A `tls.ca_pool.source` module: `inline` (`trusted_ca_certs`), `file` (`pem_files`), `system`, or `combined` (`sources`). |
| `client_certificate_file`, `client_certificate_key_file` | Present a client certificate for mutual TLS. |
| `client_certificate` | Inline PEM client certificate and key; a caddy-rs extension. |
| `server_name` | Overrides SNI and verification name. A Unix-socket upstream needs this (or `insecure_skip_verify`). |
| `insecure_skip_verify` | Disables certificate verification when explicitly `true`. |
| `handshake_timeout` | Bounds the TLS handshake. |
| `except_ports` | Dials listed upstream ports without TLS. |

### FastCGI

Set `transport.protocol` to `fastcgi` (the `php_fastcgi` Caddyfile directive does this for you).
Supported fields are `root`, `split_path`, `env`, `resolve_root_symlink`, `dial_timeout`,
`read_timeout`, `write_timeout` and `capture_stderr`. The transport speaks the FastCGI record
protocol over TCP or Unix sockets, builds the CGI environment, parses `Status:` headers and
streams both directions. Request bodies with an unknown length are buffered because FastCGI
requires `CONTENT_LENGTH`.

### PROXY protocol

- **Inbound**: add a `proxy_protocol` listener wrapper to a server with `timeout`, `allow`, `deny`
  and `fallback_policy` (`IGNORE`, `USE`, `REJECT`, `REQUIRE`, `SKIP`). PROXY protocol v1 and v2
  headers are parsed before TLS, and the parsed addresses become the connection's remote and
  local addresses.
- **Outbound**: set `transport.proxy_protocol` to `"v1"` or `"v2"` to write a PROXY header before
  the upstream request.

### HTTP/2 upstreams

`transport.versions` defaults to `["1.1", "2"]`. With `2` enabled, TLS upstreams negotiate `h2`
through ALPN and cleartext upstreams can use `h2c`. A protocol-upgrade (WebSocket) request uses an
HTTP/1.1 client even when the transport prefers HTTP/2, because upgrades cannot ride on HTTP/2.

### Header handling

The client's `Host` is forwarded unchanged unless a `headers.request` operation or the transport
changes it. Hop-by-hop headers are stripped. `X-Forwarded-For`, `X-Forwarded-Proto` and
`X-Forwarded-Host` are set from the connection; inbound values are trusted only from
`trusted_proxies`. `Via` is appended in both directions. `headers.request` and
`headers.response` support `set`, `add` and `delete`, with placeholder expansion.

## TLS

### Automatic HTTPS

Automatic HTTPS is on by default for servers that terminate TLS — that is, servers with
`tls_connection_policies`, servers listening on the effective HTTPS port (default 443), and
servers with a host matcher on a non-HTTP port. The server derives certificate subjects from host
matchers and from `apps.tls.certificates.automate`, provisions the certificates during a
configuration apply, and adds HTTP→HTTPS redirects for those hosts. Issuance failure is a located
configuration error, so the previous generation keeps serving.

Opt-outs are read from each server's `automatic_https`: `disable`, `disable_redirects`,
`disable_certificates`, `ignore_loaded_certificates`, `skip` and `skip_certificates`. Manually
loaded certificates suppress automatic management for their names unless
`ignore_loaded_certificates` is set.

Public names use the default ACME issuer. Local names (`localhost`, `*.local`, `*.internal`,
private IP addresses and other non-public subjects) use the built-in internal CA automatically, so
they work without network access.

### Internal CA

The internal issuer is Caddy-compatible: an ECDSA P-256 root and intermediate are generated and
persisted under `<data-dir>/pki/authorities/<ca-id>/`, and leaf certificates are signed under
`<data-dir>/certificates/<ca-id>/`. The default CA ID is `local`. Root lifetime is 10 years,
intermediate lifetime 7 days, and leaf lifetime 12 hours; the intermediate is rotated lazily when
it approaches expiry. `apps.pki.certificate_authorities` declares additional CA IDs (each ID also
names its directory under `pki/authorities/`); the configured `name` appears in CA metadata, and
`install_trust: false` makes `caddy-rs trust` skip that CA.

The root certificate can be exported with `caddy-rs pki export` and installed into the host trust
stores (Linux platform store, NSS/Firefox databases and Java keystores, using the tools available
on the host) with `caddy-rs trust`.

### ACME

`tls.issuance.acme` (Caddyfile `tls <email>`) supports:

- HTTP-01: the key authorization is served from the HTTP listener at
  `/.well-known/acme-challenge/<token>`.
- TLS-ALPN-01: a challenge certificate is served over the `acme-tls/1` ALPN protocol.
- DNS-01: TXT records are created through the configured provider and removed afterwards. The
  providers in this build are Cloudflare, DigitalOcean and Route 53.

Issuer settings include `ca` (directory URL, default Let's Encrypt), `email`, `account_key`,
`external_account`, `trusted_roots_pem_files`, `acme_timeout`, `network_proxy`,
`renewal_window`, and per-challenge `disabled` switches.

### Certificates and storage

`apps.tls.certificates` loads certificates without automation: `load_pem` takes inline PEM pairs,
`load_files` takes `certificate`/`key` paths (plus optional `format` and `tags`), and
`automate` lists additional subjects to manage automatically.

Storage is selected by the top-level `storage` object. The `file_system` backend uses Caddy's
on-disk layout:
`<root>/certificates/<issuer-key>/<name>/<name>.crt`, `.key` and `.json`, with CertMagic metadata
preserved across rewrites. Wildcard names are stored with `*` replaced by `wildcard_`. The data
directory defaults to `.caddy-rs`, and can be overridden with `storage.root` or the
`CADDY_RS_DATA_DIR` environment variable.

### Connection policies

`tls_connection_policies` entries support `match.sni`, `certificate_selection.any_tag`, `alpn`,
`protocols`, `curves`, `cipher_suites`/`ciphers` and `client_authentication`. The listener-wide
options (`alpn`, `protocols`, `curves`, `cipher_suites`, `client_authentication`) are applied from
the first policy.

- **Protocols**: `tls1.2` and `tls1.3`; both are enabled by default. HTTP/3 requires TLS 1.3.
- **ALPN**: `h2` and `http/1.1`, defaulting to both. A QUIC listener negotiates `h3`.
- **Ciphers**: the six ECDHE AES-GCM and ChaCha20 suites for TLS 1.2; TLS 1.3 suites are fixed.
- **Curves**: `x25519`, `secp256r1`, `secp384r1`.
- **Key types**: `p256` (default), `p384`, `rsa2048`, `rsa4096`. The internal CA always uses
  ECDSA P-256.

### Client authentication

`client_authentication.mode` is `request`, `require`, `verify_if_given` or `require_and_verify`.
Trust anchors come from the `ca` module (`tls.ca_pool.source.inline` or `.file`) or from the
`trusted_ca_certs`, `trusted_ca_certs_pem_files` and `trusted_leaf_certs` fields. When a trust
pool or leaf list is configured and no mode is given, the mode is `require_and_verify`.

### Session resumption

TLS session resumption is enabled by default. A listener that configures client authentication
disables ticket issuance and stateful session storage, so every handshake there is full; this
prevents a session authenticated under one client-auth policy from being resumed under another.

## Admin API

The admin endpoint listens on `localhost:2019` by default. Set `admin.listen` to move it, or
`admin.disabled: true` to turn it off. `admin.enforce_origin` and `admin.origins` restrict which
`Origin` values are accepted.

| Endpoint | Methods | Purpose |
|---|---|---|
| `/config/` | `GET` | Current configuration as JSON, with a strong `ETag`; `If-None-Match` yields `304`. |
| `/config/<path>` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | Read or partially update a subtree by object key or array index. |
| `/id/<id>` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | Read or update the object carrying `@id` (including nested subroutes). |
| `/load` | `POST` | Validate, provision and atomically activate a native JSON configuration. |
| `/stop` | `POST` | Deactivate the running configuration. |
| `/metrics` | `GET` | Prometheus text exposition. |
| `/adapt` | `POST` | Adapt a Caddyfile (selected by `Content-Type`) or a JSON request object to Caddy JSON. |
| `/pki/ca/<id>` | `GET` | Metadata for a provisioned local CA. |
| `/pki/ca/<id>/certificates` | `GET` | PEM chain, intermediate first and root last. |
| `/reverse_proxy/upstreams` | `GET` | Configured upstreams with their request and failure counters. |
| `/runtime/inventory` | `GET` | Read-only snapshot of the active generation, listeners, certificates and health-check schedulers (a caddy-rs extension). |
| `/debug/pprof/*`, `/debug/vars` | `GET` | Registered for compatibility; this build answers `501`. |

Partial updates follow Caddy's semantics: `PUT` creates a key (`409` if it exists) or inserts at an
array index (`len` appends), `PATCH` replaces an existing key (`404` if missing), `POST` appends to
an array or sets object keys, and `DELETE` removes a key or element. Duplicate `@id` values are
rejected with both locations. A `POST /load` of a configuration identical to the running one is a
no-op unless the request carries `Cache-Control: must-revalidate`.

## Observability

### Access logs

Access logging is configured through the top-level `logging` object. Entries are emitted only when
the active configuration contains a `logging` section. Each entry is a structured object with the
request method, host, URI, headers, peer address and TLS details, plus `bytes_read`, `user_id`,
`duration`, `size`, `status`, `resp_headers` and `write_error` (when a write failed).

- **Writers**: `stderr`, `stdout`, `discard`, `file` and `net`.
- **File rotation**: `roll` (default on), `roll_size_mb`, `roll_keep`, `roll_keep_days`,
  `roll_interval`, `roll_minutes` and `roll_at` (UTC). Rotation renames the current file to
  `<filename>.<unix-millis>`. Parent directories are created with `mode`/`dir_mode`.
- **Encoders**: `json` (default), `console`, and `filter` wrapping either. Encoder options include
  `message_key`, `level_key`, `time_key`, `name_key`, `line_ending`, `time_format`,
  `level_format` and `duration_format`.
- **Filtering**: `include`/`exclude` select logger names. Filter encoders can delete, replace,
  rename, hash, IP-mask, or act on query parameters and cookies; header filters can redact or
  remove request and response headers.
- **Redaction**: `Cookie`, `Set-Cookie`, `Authorization` and `Proxy-Authorization` header values
  are replaced with `REDACTED` by default.
- **Sampling**: `sampling.interval` (ns), `first` and `thereafter` throttle repeated entries.

Per-server `logs` (`apps.http.servers.<name>.logs`) can map hosts to named loggers with
`logger_names`, drop hosts with `skip_hosts`, or drop unmapped hosts with `skip_unmapped_hosts`.

### Prometheus metrics

`GET /metrics` serves Prometheus text format (version 0.0.4). The HTTP families are
`caddy_http_requests_total`, `caddy_http_request_duration_seconds`,
`caddy_http_request_errors_total`, `caddy_http_requests_in_flight`,
`caddy_http_request_size_bytes`, `caddy_http_response_duration_seconds` and
`caddy_http_response_size_bytes`. Proxy and certificate metric families use the
`caddy_rs_proxy_*` and `caddy_rs_tls_*` prefixes.

Metrics are recorded for every request. Labels are bounded to configuration-derived values;
request URIs and user identifiers are never used. The `apps.http.metrics` object is accepted as a
configuration shape, but its `per_host` and `otlp` options are rejected at validation.

## Operations

### Configuration generations

A configuration is provisioned as an immutable generation and swapped in atomically. Requests
hold a generation handle for their lifetime, and a replaced generation is drained after its last
in-flight request releases it. A reload that fails validation or provisioning leaves the previous
generation serving.

### Autosave and resume

The last successfully loaded configuration is written atomically to `autosave.json` after every
config transition. The path is `$XDG_CONFIG_HOME/caddy-rs/autosave.json`,
`$HOME/.config/caddy-rs/autosave.json`, or `./.caddy-rs/autosave.json`; `--autosave-path` overrides
it. `caddy-rs run --resume` loads that file in preference to `--config` when it exists. The file is
written with mode `0600`.

### Socket activation

The server adopts systemd-style inherited sockets following the `sd_listen_fds(3)` convention:
`LISTEN_PID`, `LISTEN_FDS` and `LISTEN_FDNAMES`. A TCP inherited socket is matched to a configured
listener by network and local address, a wildcard listener matches a wildcard socket, and a Unix
socket matches by path. A configured listener with no inherited socket is bound normally; an
inherited socket that no configured listener claims fails the apply with a located error. Malformed
environment values and non-listening descriptors also fail loudly.

### Command line

| Command | Purpose |
|---|---|
| `caddy-rs adapt --config <file> [--pretty] [--output <file>]` | Convert a Caddyfile (or pass through JSON) to native JSON. |
| `caddy-rs validate --config <file>` | Validate the configuration and provision its modules without serving. Prints `Valid configuration`. |
| `caddy-rs run [--config <file>] [--resume] [--autosave-path <file>]` | Run the server. |
| `caddy-rs reload --config <file>` | Load a configuration through the admin API. |
| `caddy-rs stop` | Stop the server through the admin API. |
| `caddy-rs list-modules [--json]` | List the modules compiled into this build. |
| `caddy-rs version [--json]` | Print the version and configuration baseline. |
| `caddy-rs pki list` / `pki export <id>` | Inspect and export local CA material. |
| `caddy-rs trust` | Install the local CA root into host trust stores; `--dry-run` prints the commands. |
