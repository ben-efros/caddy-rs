# Features

What this build does, by area. Configuration is written either as a Caddyfile or as Caddy JSON; see
[CONFIGURATION.md](CONFIGURATION.md).

## HTTP server

- HTTP/1.1, HTTP/2, and cleartext HTTP/2 (h2c) via prior knowledge or an upgrade request.
- HTTP/3 over QUIC. A UDP listener is derived automatically for every TLS TCP listen address when
  the server offers `h3`, so no separate address is needed; `Alt-Svc: h3=":<port>"; ma=2592000` is
  added to HTTP/1.1 and HTTP/2 responses, never to HTTP/3 responses.
- Streaming request and response bodies across all three protocols. Responses with a known length
  carry `Content-Length`; streamed responses are chunked.
- WebSocket and protocol-upgrade passthrough, extended CONNECT (RFC 8441) under Caddy's
  `GODEBUG=http2xconnect=1` gate, and RFC 6455 close-frame handling.
- Per-server limits and timeouts: header size, body size, connection caps, read/write and idle
  timeouts.
- Unix sockets, dual-stack wildcard listeners, and systemd socket activation.
- Graceful shutdown: `grace_period` with an eternal grace when unset, `shutdown_delay`, forced stop
  on a second signal, draining of ordinary connections while upgraded tunnels are closed.

## Routing

- Routes, `handle`, `route`, `subroute`, mutually exclusive `group`, `terminal`, and `@id`.
- Named routes and `invoke` from a Caddyfile.
- Error routes (`handle_errors`) with status-code matching.
- A placeholder engine covering `http.request.*`, `http.vars.*`, `http.request.header.*`,
  `http.request.cookie.*`, `http.request.tls.client.*`, `host.labels.N`, and `env.*`, applied
  consistently in rewrites, headers, responses, matchers, file paths and upstream dials.

## Matchers

| Matcher | Notes |
|---|---|
| `host` | Exact, wildcard, and placeholders |
| `path` | Exact and `*` wildcards |
| `path_regexp` | Named groups exposed to placeholders; no look-around or backreferences |
| `method` | List of methods |
| `header` | Presence, exact value, `*` suffix wildcards, and negation |
| `query` | Key presence, value matching, wildcards |
| `cookie` | Presence and value |
| `protocol` | `http/1.1`, `http/2`, `http/3` |
| `remote_ip`, `client_ip`, `local_ip` | CIDR ranges; `client_ip` respects trusted proxies |
| `tls` | Handshake completion |
| `vars` | Variable equality and regular-expression matching |
| `expression` | CEL subset: boolean operators, comparisons over strings/ints/bools, `in` lists, placeholders and request aliases |
| `file` | `root`, `try_files` with glob patterns, `try_policy`, `split_path`, `=NNN` error fallbacks |

## Handlers

| Handler | Notes |
|---|---|
| `static_response` | Status, body, headers; placeholders expanded |
| `file_server` | Root, hide, index names, browse, canonical redirects, precompressed `gzip`/`br`/`zstd` sidecars, ETag and Last-Modified, conditional and range requests, HEAD, `405 + Allow` |
| `headers` | Request and response set/add/delete |
| `rewrite` | `uri` (path, query, fragment), `method`, `strip_path_prefix`, `strip_path_suffix`, `uri_substring`, `path_regexp`, ordered `query` operations |
| `vars` | String, number and boolean request variables |
| `map` | Ordered exact and regular-expression mappings into variables, with defaults |
| `templates` | Go-template subset: conditionals, `range`, `with`, `define`/`template`, pipelines, request context and a documented function set; includes are confined to the file root |
| `request_body` | `max_size` enforcement with 413, and body replacement |
| `encode` | gzip and zstd, negotiated by `Accept-Encoding` q-values and a `prefer` order; `minimum_length`, response matcher, ETag suffixes, streaming compression |
| `authentication` / `basic_auth` | bcrypt and argon2id verification with constant-time comparison; malformed hashes fail at load |
| `forward_auth` | Canonical rewrite + `handle_response` expansion |
| `reverse_proxy` | See below |
| `rate_limit` | Token bucket per key, bounded state, configurable 429 response |

## Reverse proxy

- Upstream forms: `host:port`, `http://`, `https://`, `unix//path`, `unix+h2c//path`.
- Load balancing: `random`, `round_robin`, `first`, `least_conn`, `ip_hash`, `uri_hash`, `header`,
  `query`, `cookie`, `random_choose`, `weighted_round_robin`.
- Retries with `retry_match`, `lb_retries`, `lb_try_duration` and `lb_try_interval`.
- Active health checks scheduled per generation: `uri`, `method`, `headers`, `body`, `interval`,
  `timeout`, `passes`, `fails`, `max_size`, `expect_status`, `expect_body`, with global placeholders
  expanded in probe bodies and header values.
- Passive health checks: `max_fails`, `fail_duration`, `unhealthy_status`, `unhealthy_latency`.
- Dynamic upstreams: `srv`, `a` (IPv4/IPv6 version selection) and `multi` sources with refresh caches, SRV priority and
  weight ordering, grace-period last-known-good results, and configurable resolvers.
- Upstream TLS: system roots, inline/file CA pools, `root_ca_pem_files`, client certificates for
  mTLS, `server_name`, `insecure_skip_verify`, handshake timeouts, ALPN h1/h2.
- FastCGI: record protocol over TCP and Unix sockets, CGI environment derived from the decoded
  path, `ROOT`/`SPLIT_PATH`/`ENV`/`RESOLVE_ROOT_SYMLINK`, absolute connection deadlines,
  `SSL_PROTOCOL`/`SSL_CIPHER`, and `capture_stderr` level handling.
- PROXY protocol: listener wrappers (v1/v2, allow/deny, fallback policies, TLVs, AF_UNIX) and
  upstream headers written before TLS, HTTP/1.1 or the h2c preface.
- Streaming request and response bodies, with buffering only where retries require it.
- `handle_response` routes: status and header matchers, `replace_status`, `copy_response`,
  `copy_response_headers`.

## TLS

- Automatic HTTPS by default: certificates for host-matched sites, from ACME or the built-in CA.
- ACME: HTTP-01, TLS-ALPN-01 and DNS-01 challenges; Cloudflare, DigitalOcean and Route 53 providers;
  external account binding; configurable CA, email, timeouts and trusted roots; ARI-driven renewal.
- Internal CA: `tls internal` / `local_certs`, persisted under the Caddy layout, with `pki` and
  `trust` commands to inspect and install the root.
- Certificate storage: the Caddy/CertMagic directory layout, plus an S3-compatible backend selected
  through the top-level `storage` module.
- Connection policies: SNI and wildcard matching, per-policy ALPN, protocol versions, curves, TLS 1.2
  cipher suites, and certificate selection by tag.
- Client authentication: `request`, `require`, `verify_if_given`, `require_and_verify`; trust from
  inline, file, system, `pki_root`, `pki_intermediate`, storage, HTTP or combined sources; leaf
  certificate allow-lists; session resumption disabled on client-auth listeners.
- Certificate key types for issuance: `p256`, `p384`, `rsa2048`, `rsa4096`.

## Admin API

`/load`, `/config/` with ETag and `If-Match`/`If-None-Match`, `/id/<id>`, `/stop`, `/adapt`,
`/reverse_proxy/upstreams`, `/pki/ca/<id>`, `/metrics`, `/debug/*`, and the read-only
`/runtime/inventory` snapshot (generation, listeners, certificates, upstream counters,
health-check schedulers). Origin enforcement and config-path traversal protection are applied.

## Observability

- Structured access logs with Caddy's field set, credential redaction, JSON and console encoders,
  sampling, include/exclude filters, size/interval rotation, retention, gzip/zstd archives, and
  socket writers.
- Prometheus metrics with Caddy-compatible names, HELP text, label ordering and float formatting.

## Operations

- Atomic configuration generations: a reload either replaces the running configuration or leaves the
  previous one serving; in-flight requests drain rather than fail.
- Autosave and `--resume`; `reload` and `stop` through the admin API.
- Module inventory via `caddy-rs list-modules`.
