# Behaviour divergence register

Baseline: Caddy **v2.11.7**. This register is normative: an intentional or currently-unavoidable
difference from Caddy behaviour appears here before it ships. `tools/plan/planctl.py lint` requires
every entry to carry every field below and a tracking task that exists in `plan/`.

Fields:

- **Status** — `open` (gap to close), `planned` (gap accepted until tracked work lands),
  `accepted` (permanent, documented choice), `mitigated` (gap bounded by a safety measure),
  `out-of-scope` (deliberately not supported), `fixed` (kept for the record).
- **Caddy behaviour** — what v2.11.7 does.
- **caddy-rs behaviour** — what this build does instead, precisely enough to test.
- **Rationale** — why the difference exists.
- **Tracking** — plan task id(s) that close or own it.
- **Test** — the test that exercises the current behaviour (a gap must still have a test proving the
  failure is loud).

---

## DIV-0001 — Automatic HTTPS defaults on, with synchronous issuance and narrower derivation
- Status: mitigated
- Area: TLS
- Caddy behaviour: automatic HTTPS is on by default; listeners are derived from site addresses; certificates are provisioned/renewed asynchronously; HTTP->HTTPS redirects, challenge handlers, internal CA for local names, per-listener TLS (`port != http_port` even with explicit policies), mixed listener sets, multiple non-standard HTTPS ports and `makeRedirRoute` Location suppression apply.
- caddy-rs behaviour: automatic HTTPS defaults on for host matchers on TLS listeners. The derivation plan supports mixed cleartext/TLS listener sets (TLS every non-`http_port`, cleartext `http_port` for redirects/challenges), multiple non-standard HTTPS ports with Caddy's redirect-port winner rule, multiple servers for one host, explicit `http://host:port` servers (adapter `automatic_https.skip`), manual-certificate hosts and `ignore_loaded_certificates`, hostless catch-all TLS servers, and IP names via the internal CA. The server now applies Caddy's `makeRedirRoute` Location rule (the port is omitted when the destination equals the configured HTTP/HTTPS port or 80/443; verified live against v2.11.7) and excludes the configured HTTP port from TLS even when a server carries explicit TLS policies (`app.go`: `useTLS := len(TLSConnPolicies) > 0 && port != http_port`). Per-server `automatic_https` controls, redirects and challenge-listener derivation are honoured; tests use injected fake transports/internal-only plans. Differences: issuance is synchronous during apply (a public-CA failure fails/rolls back; Caddy retries in background); derived redirect/challenge listeners are a single wildcard `:http_port` rather than Caddy's per-bind-address redirect servers; a challenge listener is still derived under `disable_redirects`; on-demand OCSP/ACME and on-demand TLS are unsupported.
- Rationale: default-on with explicit, testable failure semantics; plan-level derivation and the observable redirect/TLS decisions are verified against the reference behaviour, and the remaining bind-address nuance is a contained follow-up.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/automatic_https.rs` plan tests, `crates/server/tests/http_auto_https.rs` (21 tests incl. redirect Location and per-listener TLS), acceptance `auto_https_internal_ca`/`auto_https_pebble`.

## DIV-0002 — ACME issuance is integrated and mock-tested; live CA walkthrough remains unproven
- Status: open
- Area: TLS
- Caddy behaviour: Obtains certificates from ACME CAs, runs challenge validation, renews before expiry, and retries failures as part of automatic HTTPS.
- caddy-rs behaviour: `AcmeIssuer` drives the full issuance flow (account, order, HTTP-01/DNS-01/TLS-ALPN-01 challenge evidence, polling, CSR, finalize, chain download) and automatic HTTPS uses it end-to-end against an in-process fake CA, persists certificates, serves them, and schedules renewals with resolver hot-swap. No live ACME CA walkthrough has been executed (offline sandbox), DNS provider construction from `challenges.dns.provider` is still caller-supplied, and cross-challenge fallback/ARI are absent.
- Rationale: the whole path is exercised deterministically offline; a live staging run needs network/credentials and is tracked for acceptance.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/issuer.rs`, `crates/server/tests/http_auto_https.rs` (fake ACME CA issuance to HTTPS serving).

## DIV-0003 — DNS-01 providers are not implemented
- Status: fixed
- Area: TLS
- Caddy behaviour: Creates and deletes DNS TXT records through provider modules and waits for propagation.
- caddy-rs behaviour: DNS-01 orchestration and the `dns.providers.cloudflare` provider are implemented and config-wired: the provider performs zone discovery, TXT create/list/delete and DNS-over-HTTPS propagation checks, and the ACME solver drives it (mock/DoH-tested offline; live Cloudflare validation remains T-COMPAT-021).
- Rationale: The provider interface and Cloudflare implementation are MS-06; the reference deployment needs them, but they depend on the ACME client.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/dns_providers.rs`, `crates/tls/src/cloudflare.rs`, `crates/tls/src/propagation.rs`, `crates/tls/src/issuer.rs` DNS-01 issuance tests.

## DIV-0004 — HTTP/3 is served over QUIC/UDP listeners, including derived ones
- Status: mitigated
- Area: HTTP
- Caddy behaviour: serves HTTP/3 over QUIC on TLS servers, auto-binds a UDP listener for every TLS TCP `listen` address when the server offers `h3` (default protocols are `[h1 h2 h3]`), and advertises `Alt-Svc: h3=":<port>"; ma=2592000` on HTTP/1.1 and HTTP/2 responses (`http3.Server.SetQUICHeaders`), which Caddy inserts for every response it serves.
- caddy-rs behaviour: binds and supervises UDP listen addresses — both explicit `udp/<addr>` forms and the ones derived automatically from TLS TCP `listen` addresses when the server offers `h3` (taken from the same reconcile path, so unchanged addresses are never rebound across reloads, removed listeners close their QUIC endpoint, and an address already covered by an explicit `udp/...` is not bound twice; cleartext servers still bind no UDP). A UDP listener must terminate TLS and the server must offer `h3`; both are located load-time errors re-checked before binding. HTTP/3 requests run through the existing `Router`/handler pipeline (method/URI/Host from `:authority`, `HTTP_3` version, peer/local addresses, `tls.alpn=h3`, trusted-proxy resolution); `static_response`, `reverse_proxy` to HTTP/1.1/HTTP/2 upstreams, the `protocol: http/3` matcher and error routes work unchanged. `Alt-Svc: h3=":<udp-port>"; ma=2592000` is added to HTTP/1.1 and HTTP/2 responses when the server offers h3 and has a bound UDP listener with a concrete port (`:0` is not advertised, matching `ErrNoAltSvcPort`); HTTP/3 responses never carry Alt-Svc. Client certificates presented on a QUIC connection are read from quinn's `peer_identity` chain and feed the same `{http.request.tls.client.*}` placeholders as the TCP path, honouring the listener's `require_and_verify`/`verify_if_given` verification mode. `apps.http.servers.<name>.allow_0rtt` (Caddy's `Allow0RTT *bool`; absent = allowed) is honoured by the QUIC TLS configuration (`max_early_data_size = u32::MAX` when allowed, `0` when explicitly `false`), and the Caddyfile `servers { 0rtt off }` form emits `allow_0rtt: false`; a non-boolean JSON value is a located apply error. Early data is accepted at the TLS layer, but caddy-rs dispatches an HTTP/3 request only after the QUIC handshake completes, so an early request is buffered until the peer is authenticated; per-request early-data state (`tls early_data` matcher, HTTP 425 `remote_ip` protection and early-data-aware remote placeholders) is not modelled. Upgrade-style requests are rejected before routing with `501 Not Implemented` and the body `501 Not Implemented: protocol upgrades are not supported over HTTP/3`: an `Upgrade` header (WebSocket) or an RFC 8441 extended CONNECT (`:protocol`, which `h3` surfaces as a request extension). Oracle-verified Caddy v2.11.9 differs at the transport boundary — quic-go rejects a plain `Upgrade` request with `H3_MESSAGE_ERROR` (no HTTP status/body) and Caddy's `reverse_proxy` tunnels extended CONNECT with `200` for a generic CONNECT — because caddy-rs buffers h3 requests and has no request-stream tunnel; this is a registered divergence.
- Rationale: HTTP/3 now works for the Caddyfile/JSON a Caddy user already has, without an explicit `udp/` line, and the previous silent protocol downgrade stays gone. Alt-Svc is added to the normal HTTP/1.1/HTTP/2 response path, the h2c `101` and the router-missing `503` (Caddy inserts it at the top of `ServeHTTP`); the `101` edge is reachable only for a cleartext listener on a server that also has a TLS listener, so it is covered by construction rather than by a test. Residual gaps: HTTP/3 request bodies are buffered before routing while response bodies now stream frame by frame (a buffered body keeps its `Content-Length`, a streamed one is sent as HTTP/3 DATA without it); one request at a time per QUIC connection; upgrade-style h3 requests are a loud 501 (Caddy's quic-go transport reset for a plain `Upgrade` and its extended-CONNECT tunnel are not reproduced) and per-request early-data signalling is absent; HTTP/3 access-log request snapshots are absent and TLS resumption/cipher metadata is approximate; no UDP systemd socket activation and no Unix-socket HTTP/3.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http3.rs` (real quinn/h3 client over real UDP listeners: static responses, h1/h2 Alt-Svc, mixed TCP+UDP, protocol matcher, reverse_proxy h1 upstream, request bodies/HEAD, reload keep/remove lifecycle with QUIC refusal after removal, loud validation, the derived-listener case where h3 enabled with only a TCP listen binds UDP and advertises it, mTLS `{http.request.tls.client.*}` placeholders, 0-RTT acceptance by default and refusal with `allow_0rtt: false`, the non-boolean `allow_0rtt` located error, and the WebSocket/extended-CONNECT 501), `crates/config/tests/upstream_adapt.rs` (`servers_0rtt_off_matches_real_caddy_v2_11_9`), `crates/core/src/validate.rs` UDP validation, oracle evidence `.scratch/logs/w14-quic-oracle` and `.scratch/logs/t-http-048-oracle` (real Caddy v2.11.9 h3 upgrade probe).

## DIV-0005 — Admin API residual response/status differences
- Status: mitigated
- Area: Admin
- Caddy behaviour: full admin surface including CORS/preflight origins, config-path null/traversal semantics, `@id` addressing, remote-admin controls, autosave, live upstream counters and exact response serialization.
- caddy-rs behaviour: config traversal/null/`@id`/ETag/preconditions, `/load`, `/stop` (a CLI-run process now exits like Caddy's `exitProcess`; embedded hosts stay unload-only), `/adapt`, `/pki`, `/metrics`, origin enforcement and CORS match the real-Caddy v2.11.7 runtime oracle. Config reads are byte-identical to Caddy's `encoding/json` output (recursively sorted compact JSON + trailing newline); the runtime oracle verifies identical bodies, ETags and Content-Length for `/config/`, subtrees and post-update reads. Malformed-body updates compare by status + `{"error": ...}` shape (DIV-0048). The runtime oracle has no admin allowlist entries: 9/9 probes pass (10 consecutive runs). Residual: admin-driven autosave is not wired (only the CLI's startup autosave is written; `admin.config.persist=false` suppresses it, and the write is 0600/0700, `O_NOFOLLOW`, regular-file/size-checked and owner-checked, with a directory `fsync`), live counter semantics (DIV-0089), and a config normalized differently by the core model could still serialize differently because the admin API serves the typed model rather than the raw loaded bytes. Remote administration (`admin.identity`/`admin.remote`, `T-ADMIN-051`/`T-ADMIN-061`) is no longer a residual: its listener, mutual-TLS and access-control behaviour is documented by DIV-0139–DIV-0145.
- Rationale: browser/config-management parity is oracle-verified without allowlists; residuals are narrow management/counter semantics.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/lib.rs` (`config_read_serialization_matches_go_encoding_json_bytes`, `stop_deactivates_the_generation_and_process_exit_is_opt_in`, malformed-body test), `crates/core/src/autosave.rs` (atomic write/0600/0700, symlink, writable-directory and 16 MiB read refusals), `crates/cli/tests/cli.rs` (`run_honours_admin_config_persist_false_and_does_not_autosave`), `tools/compat/oracle/scenarios/{admin-mutation,admin-stop}`, evidence `.scratch/logs/w10-admin-oracle-final-evidence-*.json` and `.scratch/logs/w10-admin-parity-evidence.txt`.

## DIV-0006 — Metrics, observability, request correlation and debug endpoints
- Status: mitigated
- Area: Admin / HTTP
- Caddy behaviour: experimental `apps.http.metrics` enables the `caddy_http_*` series; `http.handlers.metrics` serves `/metrics`; JSON access logs follow `modules/caddyhttp/logging.go` and `marshalers.go` and include extra fields `uuid` (from `{http.request.uuid}`, lazily generated, log-only) and `traceID`/`spanID` (from the OpenTelemetry `http.handlers.tracing` handler, which also injects `traceparent`/`tracestate` into upstream requests). Caddy's admin mux always registers `/debug/pprof/` (+ `cmdline`/`profile`/`symbol`/`trace`) and `/debug/vars` (`admin.go:268-274`), serving Go pprof/expvar data; exposure is limited by the admin listener address (default localhost:2019), not by a config flag.
- caddy-rs behaviour: metric names, HELP text, label names/order (`le` last), Go `%g` float presentation and the scrape content type match Caddy v2.11.7 for the `caddy_http_*` families; the access-log model supports Caddy's `uuid`/`traceID`/`spanID` fields with the exact keys, including a lazy cached UUIDv4 helper (`RequestUuid`) and uniqueness tests; `http.handlers.tracing` config (`span`, `span_attributes`) is parsed and validated with located errors, and `apps.http.servers.*.tracing` is documented as not a v2.11.7 surface. The Caddyfile logging subset (site/global `log`, `debug`, `metrics`) adapts to Caddy's exact JSON. Deliberately absent: `{http.request.uuid}` placeholder expansion and access-entry population (needs `crates/http` + server wiring), the tracing handler itself, W3C context injection into upstreams, `trace_id`/`span_id` request variables and the `traceID`/`spanID` log fields (need an OpenTelemetry exporter dependency), and live `per_host`/OTLP metrics. The `per_host` label policy and its configuration scan now implement upstream `fe69f5da2d74`'s bounded rule (HTTPS is not an exemption, labels are lowercased without a port, and host matchers are collected from `subroute`/`handle` chains, server error routes and `named_routes`), but `per_host` remains rejected by `core::validate` until the opt-in gate is wired, so no live series change yet (`T-PORT-fe69f5da2d74`). The Go debugging endpoints are registered routes in caddy-rs but answer a located, documented `501 Not Implemented` (`T-ADMIN-022`) with no fake data; `/debug/pprof` 307-redirects and non-GET returns 405. Remaining runtime gaps from the metrics work stand: metrics always recorded (no opt-in gate), empty `handler` label, `request_size` from declared Content-Length, no `Server: Caddy` header, `bytes_read` for streamed bodies, no OpenMetrics negotiation and no `http.handlers.metrics` handler.
- Rationale: scrape format and the Caddyfile logging surface match the reference behaviour, unsupported observability features fail loudly and are documented instead of approximated, and the access-log/tracing-config pieces are the reusable half needed by the http/server hooks.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/metrics.rs`, `crates/admin/src/access_log.rs` (uuid/trace/unique/lazy tests), `crates/admin/src/metrics_config.rs`, `crates/admin/src/tracing_config.rs` (config parse/reject), `crates/admin/src/lib.rs` (debug endpoint tests), `crates/server/tests/http_observability.rs`, `crates/server/tests/http_per_server_logs.rs`, `crates/config/tests/logging.rs`, curated `log_*`/`metrics_otlp` fixtures, the `access_log_json` acceptance scenario, and oracle evidence under `.scratch/logs/w12-admin-oracle/` and `.scratch/logs/w14-admin-oracle/`.

## DIV-0007 — Placeholder expansion covers the request path; some response/log consumers remain
- Status: open (narrowed by T-ROUTE-042)
- Area: Routing
- Caddy behaviour: expands a large placeholder vocabulary (`{http.request.*}`, `{http.vars.*}`, `{env.*}`, `{http.reverse_proxy.*}`, `{http.response.*}`, time/system values, regexp captures) in rewrites, header values, matcher patterns, upstream dials, file-server and file-matcher paths, logs and more. `file` matcher `root` uses `filepath.Clean(repl.ReplaceAll(root, "."))`, and `try_files` uses `ReplaceFunc` with glob-escaped replacement values.
- caddy-rs behaviour: a single-pass Replacer implements `http.request.{method,scheme,host,hostport,port,remote...,uri,uri.path...,uri.query...}`, `http.request.header.*`, `http.request.cookie.*`, `host.labels.N`, `vars.*` and `env.*`, with Caddy's unknown-placeholder semantics (left verbatim in `ReplaceKnown`, empty in `ReplaceAll`). It is applied in rewrite `method`/`uri`/`strip_path_prefix`, `static_response` body/headers, `headers`, `vars`, matcher patterns (host/path/query/header values, `ReplaceAll`), `file_server` `root`/`hide`/`index_names` (`ReplaceAll`, traversal rejection preserved), `file` matcher `root` (per-request `ReplaceAll` with Caddy's `.` fallback and Go path cleaning) and `try_files` (glob-safe `ReplaceFunc`-style expansion, unknown values blank), and `reverse_proxy` dynamic upstream dials (`ReplaceAll`, validated address, located per-request 502 on empty/invalid expansion) plus request/response header operations and `handle_response` copied headers (`ReplaceKnown`). Not expanded: `{file.*}` placeholders, access-log fields and other `{http.response.*}` consumers outside the Replacer; dynamic upstreams reject active health checks and FastCGI loudly, admin `/reverse_proxy/upstreams` reports the template dial with aggregated counters, and passive health is keyed by the template.
- Rationale: the Replacer and the request-path consumers relevant to routing/file serving are implemented and tested; remaining consumers are tracked rather than silently approximated.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/placeholders.rs`, `crates/http/src/handlers.rs`, `crates/http/src/router.rs`, `crates/http/src/matchers.rs` (matcher expansion incl. file-matcher root switching/empty fallback/containment), `crates/http/src/file_server.rs` (root/hide/index_names expansion + traversal guard), `crates/proxy/src/handler.rs` (dynamic dials incl. real-listener E2E, invalid/empty located errors, header `ReplaceKnown`) and `crates/proxy/src/upstream.rs`; oracle evidence `.scratch/logs/w23-file-match/comparison-final.txt`.

## DIV-0008 — `encode` compresses responses with gzip/zstd
- Status: fixed
- Area: HTTP handlers
- Caddy behaviour: `http.handlers.encode` negotiates gzip/zstd/brotli via `Accept-Encoding` q-values and `prefer` order, applies a response matcher and `minimum_length` (default 512), sets `Content-Encoding`/`Vary: Accept-Encoding`, removes `Content-Length`/`Accept-Ranges`, suffixes strong ETags with `-<encoding>` (stripping it from `If-None-Match` before handlers), never encodes 1xx/204/206, adds `Vary` to 304s, honours `no-transform`, and streams compressed bodies. Encoders are klauspost gzip (default level 5) and klauspost zstd (`fastest`/`default`/`better`/`best`, 128 KiB window, checksum on by default).
- caddy-rs behaviour: `encode` implements the Caddy JSON shape (`encodings`, `prefer`, `minimum_length`, custom `match` response matcher with status/header wildcards), Caddy's default preference order and defaults (minimum_length 512 including an explicit `0`, gzip level 5 including an explicit `0`, zstd `default` level with checksum enabled unless disabled), full `AcceptedEncodings` negotiation (q-values, server-preference tie-break, `q=0` rejected, exact names only so `*` does not match, WebSocket handshakes excluded), request/response `no-transform`, content-type sniffing for a missing `Content-Type`, the minimum-length rule (first chunk or Content-Length strictly greater), removal of `Content-Length`/`Accept-Ranges`, `Content-Encoding`/`Vary` handling without duplicates, strong-ETag suffixing plus `If-None-Match` suffix stripping, 304 `Vary`, no encoding of 1xx/204/206, error-path encoding disable (so `handle_errors` responses are not compressed by an earlier `encode`), and streaming compression of `Body::Stream` responses. The Caddyfile adapter already emits Caddy-identical JSON; `prefer` is JSON-only because Caddy v2.11.7 has no Caddyfile `prefer` subdirective (the adapter rejects it like Caddy).
- Rationale: compression is a production-critical response middleware; a generic response-transform hook keeps it inside `crates/http` and preserves end-to-end streaming without server changes.
- Tracking: T-COMPAT-003
- Test: `crates/http/tests/encode.rs` (9 router-level tests incl. streaming-first-frame proof, negotiation matrix, 304/204/206, error disable, Caddyfile adaptation parity), `crates/http/src/encode.rs` (16 unit tests), real-Caddy v2.11.7 evidence under `.scratch/logs/w15-encode-oracle/`.
- Residual divergences: compressed payload bytes (and therefore `Content-Length`) differ from Caddy because caddy-rs uses `flate2`/`zstd` while Caddy uses klauspost's Go codecs — decompressed representations and all header semantics are identical (zstd frame checksum presence matches Caddy's default); gzip's negative "stateless"/"constant" levels are rejected loudly; HEAD compressed responses match `Content-Encoding`/`Vary`/ETag but their `Content-Length` can differ; an `encode` inside a subroute whose inner chain produces no response registers a transform that may apply to a later outer-handler response; unknown JSON fields are rejected loudly (Caddy ignores them); content-type sniffing is a conservative `DetectContentType` subset.

## DIV-0009 — Responses stream end to end; request bodies and static-file handlers are still buffered
- Status: mitigated
- Area: Proxy / HTTP
- Caddy behaviour: Streams request and response bodies (subject to request_buffers/response_buffers) and supports `flush_interval` for SSE.
- caddy-rs behaviour: The HTTP engine has a `Body` abstraction and `Router::handle_streaming`; the server connection boundary now returns hyper streaming bodies, so `reverse_proxy` responses stream end to end (first byte before upstream end, chunk boundaries/trailers preserved, mid-stream errors abort after headers, client disconnect cancels upstream, unknown-length responses framed without Content-Length). Request bodies are still collected into `Bytes` (T-PROXY-039), handlers that build a fixed `Bytes` body (`file_server`, `static_response`, auth subrequests) remain buffered, and positive `flush_interval` is accepted but every frame flushes immediately (equivalent to Caddy's default `-1`).
- Rationale: response streaming covers the reference deployment (media downloads/SSE); request-body and file-streaming follow-ups are tracked.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/body.rs`, `crates/server/tests/http_streaming.rs`, `crates/proxy/src/handler.rs` streaming tests.

## DIV-0010 — TLS upstreams support mTLS and CA pools; automation/curves/Caddyfile emission remain open
- Status: open
- Area: Proxy
- Caddy behaviour: TLS upstreams with system trust, `ca` module pools (inline/file/system/combined/pki_root/pki_intermediate/storage/http), client certificates (static file pair or automated), curves, `except_ports`, renegotiation, HTTP/2/h2c protocols; module configuration is decoded strictly, so unknown transport/TLS fields are errors.
- caddy-rs behaviour: rustls TLS upstreams implement trust discovery; deprecated `root_ca_pool` (base64 DER list) and `root_ca_pem_files` (PEM paths) replace the system store, are merged and conflict with `ca`; `ca` inline/file/system/combined providers; static `client_certificate_file`/key mTLS loaded and validated at configuration load (missing file, bad PEM, encrypted key, cert/key mismatch are located errors); `insecure_skip_verify`, `server_name` SNI/verification override, `handshake_timeout`, `except_ports` and `renegotiation: never`; ALPN h1/h2 and h2c; unknown `transport.tls` fields are rejected like Caddy's strict module decoding. caddy-rs extension: inline `client_certificate: {"certificate","key"}` PEM client certificates (Caddy v2.11.9 strict-rejects this unknown field — oracle-verified — and it is mutually exclusive with the file fields). Still unsupported (loud): `client_certificate_automate`, explicit `curves`, pki/storage/http CA providers, `renegotiation` once/freely and cert reload/OCSP config. Caddyfile `transport http` TLS suboptions (`tls_client_auth`, `tls_trusted_ca_certs`, `tls_trust_pool`, `tls_server_name`, `tls_timeout`, `tls_renegotiation`, `tls_except_ports`, `tls_curves`) emission remains adapter work (`crates/config`, T-PROXY-046); the JSON form is complete. `except_ports` matches the upstream dial port rather than a rewritten request port.
- Rationale: static mTLS and CA pools cover reference deployments; inline PEM is a caddy-rs convenience for generated configurations; automation is a larger lifecycle feature.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/tls.rs` (field parsing, strict unknown fields, deprecated pools merged, CA providers, client-certificate error paths), `crates/proxy/src/handler.rs` real-TLS tests (mTLS file+inline, wrong/missing client cert, `root_ca_pool` trusted/rejected, CA module file/inline, `server_name` override/mismatch, insecure mode, `handshake_timeout`, `except_ports`, h2), oracle JSON validations for file fields/`handshake_timeout`/unknown-field rejection.

## DIV-0011 — WebSocket upgrades are not proxied
- Status: fixed
- Area: Proxy
- Caddy behaviour: Upgrades HTTP/1.1 connections to WebSocket and proxies the bidirectional stream.
- caddy-rs behaviour: WebSocket/Upgrade passthrough is implemented end to end for HTTP/1.1 over cleartext and TLS (handshake, bidirectional byte tunnel, shutdown propagation); DIV-0076 records the implemented close-frame behaviour (1001 shutdown / 1000 upstream EOF).
- Rationale: Upgrade passthrough requires connection-level plumbing in the server (T-PROXY-032); it is required for the Jellyfin acceptance scenario.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_websocket.rs`, `crates/proxy/src/handler.rs` upgrade/WebSocket tests, local acceptance scenario `websocket_proxy`.

## DIV-0012 — Renewal timing has certmagic-compatible ARI with deterministic fallback
- Status: open
- Area: TLS
- Caddy behaviour: certmagic renews at one third of lifetime remaining with random jitter and consults ACME Renewal Information (RFC 9773): fetches `renewalInfo`, selects a uniform random time in `suggestedWindow`, renews at `selectedTime - RenewCheckInterval` (default 10 minutes), honours an emergency window (last 1/20 of lifetime), respects `Retry-After`, and uses storage locks across instances.
- caddy-rs behaviour: `RenewalPolicy` renews at integer-exact `not_after - lifetime/3` with deterministic per-name jitter (0-10 min), exponential backoff (30 s to 1 h, in-memory), per-certificate dedup, and now ARI: the leaf certID is built from the AKI key identifier plus the DER serial, `suggestedWindow`/`explanationURL`/`Retry-After` are parsed, a uniform random renewal time is selected inside the window, the scheduler caches ARI per certificate, refreshes at `Retry-After`, renews at `selected_time - check_interval` (default 10 min), always honours the emergency window, prefers an earlier ARI window over the local heuristic, and falls back to the local heuristic when ARI is absent/404/failed. ARI tests use the scripted mock transport only. Remaining gaps: ARI is in-memory only (not persisted into certmagic `issuer_data.renewal_info`), it is fetched by the scheduler rather than proactively on handshake/manage, and OCSP-driven renewal plus distributed locks remain absent.
- Rationale: ARI makes CA-driven renewal timing testable offline and deterministic under the manual clock; the residual persistence/proactive-fetch work does not change renewal correctness.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/acme/ari.rs` (`parses_rfc3339_with_offsets_and_fractions`, `rejects_invalid_windows`, `selects_uniform_time_inside_window`), `crates/tls/src/acme/mod.rs` (`fetches_mock_ari_window_and_falls_back_when_unavailable`), `crates/tls/src/renewal.rs` (`ari_selected_time_overrides_the_local_renewal_heuristic`, `ari_can_renew_earlier_than_the_local_heuristic`, `ari_failure_or_absence_falls_back_to_the_local_heuristic`).

## DIV-0013 — Certificate storage uses the Caddy/CertMagic directory shape with a metadata subset
- Status: open
- Area: TLS
- Caddy behaviour: CertMagic stores certificates under `<data-dir>/certificates/<issuer-key>/<name>/<name>.{crt,key,json}` with locking, OCSP/PKI/lock directories and a full `CertificateResource` metadata JSON.
- caddy-rs behaviour: `FileStorage` reads and atomically writes the same certificate directory shape (`<issuer-key>` from the CA URL or internal CA id, `wildcard_` name mapping, PEM chain + key + a `{"sans":[...]}` metadata subset). It does not implement CertMagic locking, `acme/`, `ocsp/`, `locks/`, `pki/` directories, and rewriting an existing metadata file drops unknown CertMagic fields such as `issuer_data` (DIV-0051).
- Rationale: Reusing the data-directory shape is the migration requirement; distributed locking and metadata fidelity follow with the issuer integration.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/tests/caddy_storage.rs` + fixtures under `crates/tls/tests/fixtures/caddy-data/`.

## DIV-0014 — Caddyfile imports and named routes are implemented; imported-file names are missing from some error locations
- Status: mitigated
- Area: Caddyfile
- Caddy behaviour: `import` supports files, globs, snippets and arguments; errors reference the source file; named routes/`invoke` adapt to `named_routes`.
- caddy-rs behaviour: file/glob imports (relative to the supplied config path), args/`{block}`, env expansion in imported files, cycle detection, named-route `&(name)` definitions and `invoke` JSON are implemented and match Caddy fixtures. Errors raised *inside* an imported file carry the right line but not the imported filename because `Position` has no source-file field; stdin adaptation (no source path) rejects file imports loudly.
- Rationale: accepted/rejected behaviour matches; enhanced source locations are a diagnostics follow-up.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/import_named_routes.rs`, curated upstream import/named-route fixtures.

## DIV-0015 — `path_regexp` runs on the linear-time `regex` crate
- Status: fixed
- Area: Routing
- Caddy behaviour: Matches request paths with RE2 regular expressions and publishes numeric and named capture groups as `{http.regexp.capture}` / `{http.regexp.name.capture}`; the rewrite form replaces with `$1`/`$name`.
- caddy-rs behaviour: the matcher and `uri path_regexp` rewrite compile with the `regex` crate (linear-time, no backtracking) through the shared `caddy-rs-core` regex wrapper; named `(?P<name>…)`/`(?<name>…)` groups, word boundaries, lazy quantifiers and mid-pattern inline flags work; captures are published in Caddy’s scoped and unscoped forms. Look-around and backreferences are rejected with a located `pattern`/`find` error, as in Go’s RE2. Residual: Rust’s `\w`, `\d`, `\s` and `\b` are Unicode-aware while Go’s are ASCII; `.` remains scalar-correct because `unicode(false)` would reject common `.*` patterns on `&str`. The admin access-log `regexp` and `multi_regexp` filters use the same shared `caddy-rs-core` regex wrapper, with Go-compatible replacement expansion for **well-formed ASCII references** (`$N`/`${N}`/`$name`/`${name}`, non-participating or absent groups expanding to nothing, and longest-parse unbraced names). Malformed references diverge from Go's `Regexp.ReplaceAllString`: for pattern `(a)` and input `a`, Go expands `$01` and `${01}` to the empty string and keeps `${}` and `${a b}` literal, while caddy-rs expands `$01`/`${01}` to the first group and drops `${}`/`${a b}`; Go also treats `$é` as a reference to an absent (Unicode-named) group and expands it to the empty string where caddy-rs leaves it literal. This is registered as the DIV-0015 reference-parsing residual and asserted on the caddy-rs side by `regexp_filter_malformed_reference_parsing`; the Unicode `\b`/`\w`/`\d`/`\s` residual above applies to filter patterns too.
- Rationale: a maintained linear-time engine removes the hand-written backtracking VM and its ReDoS/step-limit risk; unsupported non-RE2 constructs still fail closed.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/matchers.rs` (`path_regexp_publishes_named_captures`, `path_regexp_supports_re2_constructs`, `path_regexp_rejects_non_re2_constructs_loudly`), `crates/http/tests/matchers_fixtures.rs` (adapted named-capture route), `crates/http/tests/rewrite.rs` (`path_regexp_rewrite_supports_named_and_numeric_captures`), `crates/core/src/regex.rs` wrapper tests.

## DIV-0016 — Unsupported configuration fails instead of being approximated
- Status: accepted
- Area: Compatibility policy
- Caddy behaviour: Accepts the full Caddy module/configuration surface.
- caddy-rs behaviour: Any module, directive, matcher or app this build does not implement is rejected with a located error naming it and the tracking task (unknown module, unsupported directive, or `NotImplemented`). There is no silent fallback to different semantics.
- Rationale: This is the program's core safety property: a configuration that loads is one whose semantics are implemented. Approximation would make divergence invisible.
- Tracking: T-COMPAT-003 T-CONF-010
- Test: `caddy-rs/crates/cli/tests/cli.rs::adapt_surfaces_unsupported_directive_as_error` and `crates/core` validation tests.

## DIV-0017 — HTTP→HTTPS redirects are generated only for explicit automatic-HTTPS policies
- Status: mitigated
- Area: TLS / Runtime
- Caddy behaviour: Automatic HTTPS generates HTTP-port redirect routes for site addresses by default, per-site scheme rules apply, and `auto_https disable_redirects`/`off` modify this.
- caddy-rs behaviour: When automatic HTTPS is explicitly configured, the server derives an HTTP listener on `apps.http.http_port` (default 80) that serves ACME challenges and returns 308 redirects preserving path/query for managed hosts; `disable_redirects`, `auto_https off`, `skip`/`skip_certs` are honoured. Without explicit `apps.tls.automation`/`certificates.automate` no redirects are generated (see DIV-0001); redirects are not generated for Caddyfile output that lacks explicit automation.
- Rationale: redirects are part of the explicit automatic-HTTPS subset.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_auto_https.rs` (308 redirect, disable_redirects, auto_https off).

## DIV-0018 — caddy-rs admin extension endpoints (`/healthz`, `/runtime/inventory`)
- Status: accepted
- Area: Admin
- Caddy behaviour: Caddy v2.11.7's admin mux registers `/config/`, `/id/`, `/stop` and `/debug/*` (`external/caddy/admin.go:264-274`); module-owned `admin.api` routes add `/metrics`, `/reverse_proxy/upstreams` and `/pki/` (`admin.go:278-290`, `modules/caddypki/adminapi.go`). There is no general runtime-inventory endpoint.
- caddy-rs behaviour: exposes read-only caddy-rs extensions `GET /healthz` and `GET /runtime/inventory` in addition to the Caddy-compatible routes. `/runtime/inventory` returns the active generation (id, lifecycle state, xxh64 config hash, Unix load time/uptime), runtime/snapshot synchronisation (`runtime.applied_generation_id`, `runtime.in_sync`, `snapshot.available`, `snapshot.stale`), the admin listener, configured/bound HTTP listeners (network, TLS, protocols, HTTP/3 flag), managed-vs-loaded certificates (subject, SANs, issuer, Unix `not_after`, `source: "managed"|"loaded"`), per-upstream live counters (`health` is null until the proxy exposes active-health state), and active health-check scheduler generations/counts. The server installs a complete snapshot after every successful apply and clears it on shutdown; the endpoint copies it under a lock (never blocks a reload) and represents a missing generation, no server source, and a failed-apply/mid-reload store/runtime mismatch explicitly with a note rather than reporting stale data as current. Only GET is allowed (405 otherwise) and the shared admin origin/host policy applies.
- Rationale: operators need listeners/generations/certificates/health in one read-only view; Caddy scatters this across config/module endpoints and logs. The endpoint is additive, clearly marked, and never fabricates proxy health.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/lib.rs` (`runtime_inventory_*` tests incl. origin policy, 5,000-listener response bound, missing/stale representation), `crates/server/tests/http_runtime_inventory.rs` (real listeners, loaded-certificate expiry/SAN inventory, reload freshness, failed-apply honesty, read-only 405).

## DIV-0019 — Proxy failure status/body selection differs from Caddy
- Status: accepted
- Area: Proxy
- Caddy behaviour: Returns 502 for upstream failures (with its standard error handling) and specific statuses for health/retry exhaustion.
- caddy-rs behaviour: With no selectable upstream before any attempt it returns `503 Service Unavailable`; after a failed attempt and retry exhaustion it returns `502 Bad Gateway`; both have a plain-text body. Caddy's exact error body and status selection may differ.
- Rationale: The distinction between "no upstream ever available" and "upstream recently failed" is operationally useful; the bodies are intentionally simple until error routes exist.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/proxy/src/handler.rs` asserts the 502 path; the 503 path is exercised by an empty/health-down pool test.

## DIV-0020 — Graceful shutdown drain, grace period and forced stop
- Status: fixed (residuals noted below)
- Area: Server / Core lifecycle
- Caddy behaviour: `App.stop` (`modules/caddyhttp/app.go`) honours `shutdown_delay` for closing listeners, starts a grace-period context when `grace_period > 0`, and otherwise uses an eternal grace period (`Shutdown(context.Background())`). Go's `http.Server.Shutdown` waits for active requests and idle connections but ignores hijacked connections. A reload does not wait for the grace period unless the process is exiting; process exit waits for all server shutdowns (including earlier reload shutdowns via `pendingServerShutdowns`); a second SIGINT/SIGTERM force-quits immediately.
- caddy-rs behaviour: `shutdown_delay` keeps listeners accepting before the grace period, including listeners closed by a reload (the old listener keeps accepting during the delay, then its connections are bounded by the grace timer); an absent/zero `grace_period` is Caddy's eternal grace period for ordinary connections; hijacked/upgraded tunnels are excluded from the eternal wait (matching Go's `Shutdown`) and are closed as shutdown completes; grace expiry or a second signal force-closes all connections; forced shutdown waits (bounded) for connection tasks to drop their tracker guards before listener teardown; failed applies leave the previous generation serving. Residual: Caddy's `pendingServerShutdowns` cross-reload wait at process exit and its cross-config `ListenerUsage` shared-listener check are not modelled.
- Rationale: aligns shutdown drain/exit semantics with Caddy without inventing behaviour; remaining differences are visible in logs and covered by tests.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_graceful_shutdown.rs` (`slow_request_completes_with_eternal_grace_period`, `upgraded_tunnel_does_not_hang_eternal_grace_period`, `reload_honors_shutdown_delay_and_grace_for_closing_listeners`, `fifty_concurrent_slow_requests_drain_with_eternal_grace`, `forced_shutdown_aborts_fifty_in_flight_requests_and_releases_listener`), existing `http_observability` flush tests, `crates/core/src/generation.rs` cancellation/cleanup tests.

## DIV-0021 — Connection and request-body limits are partially enforced
- Status: mitigated
- Area: HTTP
- Caddy behaviour: Enforces `read_timeout`, `write_timeout`, `read_idle_timeout`, `write_idle_timeout`, `read_min_rate`, `write_min_rate`, `max_write_chunk`, `idle_timeout` (default 5m), `read_header_timeout` (default 1m), `max_header_bytes`, HTTP/2 tuning, and route-level `request_body` caps.
- caddy-rs behaviour: `idle_timeout` (default 5m), `read_header_timeout` (default 1m), `max_header_bytes` (default 16 KiB), and per-operation read/write stall timeouts are enforced; server-level `max_request_body_size` (413) and `max_connections` are caddy-rs extensions (DIV-0036). HTTP/2 stream/frame/window tuning has no Caddy v2.11.7 JSON fields (Caddy passes `new(http2.Server)`, i.e. Go defaults), so caddy-rs pins hyper's h2 server explicitly to the Go-compatible values: `MAX_CONCURRENT_STREAMS=250`, `MAX_FRAME_SIZE=1 MiB` (1048576; Go `MaxReadFrameSize` default, advertised via `SETTINGS_MAX_FRAME_SIZE`), 1 MiB initial stream/connection windows, and `MAX_HEADER_LIST_SIZE = max_header_bytes + 320` (Go `http2adjustHTTP1MaxHeaderSize`); h2c-upgraded connections get the same settings and an idle HTTP/2 connection is closed by `idle_timeout`. Invented h2 tuning fields are rejected loudly at server apply. `read_idle_timeout`/`write_idle_timeout`/min-rate/max-chunk remain unenforced; Caddy's `keepalive_*` are TCP keepalive options, not h2 PING, and remain unenforced; `enable_full_duplex` is HTTP/1-only; extended CONNECT is advertised/accepted only under the Caddy/Go `GODEBUG=http2xconnect=1` gate (DIV-0071). Generic rejection of unknown server fields remains a core-config follow-up. The `request_body` handler is not registered; read/write granularity differs (DIV-0037).
- Rationale: hyper 1.x exposes per-I/O timeouts, not whole-transfer deadlines; stalled clients are still cut off and body caps are available server-wide.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/server/src/limits.rs`, `crates/server/tests/http_limits.rs`, `crates/server/tests/http2_settings.rs`.

## DIV-0022 — Adapter route grouping and internal group names may differ
- Status: accepted
- Area: Caddyfile adapter
- Caddy behaviour: Consolidates adjacent identical-matcher routes and numbers `handle` groups with an internal counter; site-block ordering follows host specificity.
- caddy-rs behaviour: Route/site-block ordering now matches Caddy for the supported directives, adjacent routes are consolidated, and all `handle`/`handle_path` routes in a body share the internal group name `group1`. Group names are internal; the conformance comparison normalises them.
- Rationale: Group names do not affect route semantics. Adapter parity is verified against 34+ curated upstream fixtures with zero mismatches on supported constructs.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/config/tests/upstream_adapt.rs` (12 tests), `docs/compatibility/ADAPT-CONFORMANCE.md`.

## DIV-0023 — CLI output is not byte-identical to Caddy
- Status: accepted
- Area: CLI
- Caddy behaviour: `caddy version`, `list-modules`, `adapt`, `fmt` diagnostics, startup banners and error formatting have specific outputs. Runtime failures exit 1 through Cobra, including usage errors (unknown flag, missing flag value), which print `Error: ...`; command errors are structured zap records (`{"level":"error",...,"msg":"..."}` when stderr is not a terminal).
- caddy-rs behaviour: Commands follow the same verbs and success/failure conventions, and `fmt`'s formatted output, `--diff` rendering, `--overwrite` file bytes and located `file:line:` message body are byte-identical to Caddy v2.11.9. Text output still differs: errors are printed as `caddy-rs: error: <message>` with no zap envelope, `version --json`/`list-modules --json` are stable caddy-rs shapes, the help footer lacks Caddy's documentation URL, and clap usage errors exit 2 with clap's `error:` text where Cobra exits 1 with `Error: ...`. The usage-error exit code is documented in `docs/CLI.md` and asserted by existing tests. Four verbs are caddy-rs-only and have no Caddy equivalent: `completion install`, `completion uninstall` and `completion status` (the ownership-marked per-user installer; `completion <shell>` itself only prints the script, as in Caddy) and `pki export`. They are additions, not changes to a Caddy verb: they never run implicitly, `completion install` writes only its marker-owned files under `XDG_DATA_HOME`/`XDG_CONFIG_HOME` (refusing foreign files and symlinked targets, writing atomically) and never edits a shell rc file or `$PROFILE`, and `completion uninstall` removes only files carrying that marker.
- Rationale: Scripts depend on verbs, exit codes and formatted output, not on banners or the error envelope; JSON shapes are documented and stable. Byte-identical CLI diagnostics are a non-goal, and changing the clap usage exit code would alter every existing command's documented contract.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/cli/tests/cli.rs` covers verbs, exit codes, JSON contracts and the `fmt_*` cases (formatted output, `--diff`, `--overwrite`, stdin, located message, multiple-input error); `crates/cli/src/fmt.rs` carries the upstream formatter corpus.

## DIV-0024 — File serving mirrors Caddy/Go but keeps a curated MIME table
- Status: mitigated
- Area: HTTP handlers
- Caddy behaviour: Uses OS MIME databases (`/etc/mime.types`), supports `If-Match`/`If-Unmodified-Since`/`If-None-Match`/`If-Modified-Since`/`If-Range`, single and multipart range requests, `ETag`/`Last-Modified` emission, precompressed variants and `HEAD`, with Go `net/http.ServeContent` semantics.
- caddy-rs behaviour: static file transfers follow Caddy v2.11.7 / Go `ServeContent` — strong `Etag: "<mtime-nanos base36>-<size base36>"` (or the `etag_file_extensions` sidecar) plus RFC1123 `Last-Modified` for useful mtimes, `Accept-Ranges: bytes`, conditional requests evaluated in Go's order (`If-Match` -> `If-Unmodified-Since` -> `If-None-Match` -> `If-Modified-Since` -> `If-Range`) with 304/412/416 responses and Go's header/body shapes, single and multipart byte ranges (206 with Go part framing and computed length), `HEAD`, `405 + Allow: GET, HEAD`, 308 canonical redirects, and `Vary: Accept-Encoding`. `precompressed` selects `.gz`/`.br`/`.zst` sidecars by Accept-Encoding q-value with `precompressed_order` breaking ties, keeps the original `Content-Type`/`Last-Modified`, uses the sidecar length/ETag, applies ranges to the encoded representation and falls back to the original when the sidecar is missing. Residual differences: the MIME table is a curated extension->type table instead of a runtime `/etc/mime.types` load (rare extensions may differ; caddy-rs omits `Content-Type` rather than guessing), `browse` object options beyond enabling browsing are ignored (boolean enablement), canonical redirects use the current (possibly rewritten) URI rather than Caddy's original path, `file_server.hide` placeholders are not expanded, custom `fs` modules are loudly unsupported, and multipart boundaries are random (bodies structurally identical, not byte-identical).
- Rationale: everything the media/Jellyfin workload needs (ranges, conditionals, ETags, precompressed) now matches the reference behaviour, verified against real Caddy v2.11.7 captures; the residual differences are host-dependent or documented subsets, never silent approximations.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/http/src/file_server.rs` unit tests (MIME, traversal, ranges, conditionals, precompressed, redirects) and `crates/http/tests/file_server_oracle.rs` (35-case real-Caddy replay: identical status/headers/body).

## DIV-0025 — Admin config traversal return semantics are simplified
- Status: fixed
- Area: Admin
- Caddy behaviour: missing leaf reads `null` (200), traversal through missing/scalar nodes is a 400 with `invalid traversal path at: config/<full path>`, array indices have canonical/bounds messages and `@id` expansion works.
- caddy-rs behaviour: matches the oracle: null leaf 200 + ETag, 400 full-path traversal messages, array index reasons, numeric `@id` and nested `/id` reads with expanded-path ETags (2026-11-05). Only exotic Go ServeMux canonical-redirect quirks outside `/pki/` are not emulated.
- Rationale: common config-management paths are now exact.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/lib.rs` config-path tests, oracle probes.

## DIV-0026 — Advanced load-balancing policies are config-only
- Status: fixed
- Area: Proxy
- Caddy behaviour: `weighted_round_robin`, `ip_hash`, `uri_hash`, `header`, `query`, `cookie`, `random_choose` and `random` policies select upstreams; weights are honoured; `random` is the default policy.
- caddy-rs behaviour: every Caddy policy is now implemented at runtime with Caddy-compatible semantics (rendezvous hashing for ip_hash/uri_hash, HMAC-SHA256 sticky cookies for cookie, reservoir sampling for random/random_choose, weights for weighted_round_robin), and the adapter emits `selection_policy.policy`/`weights` faithfully. Unknown policy names still fail loudly by name rather than silently approximating.
- Rationale: full policy parity; fail-closed is retained only for genuinely unknown names.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/balancer.rs` selection-policy tests; adapter parity covered by the conformance classifier.

## DIV-0027 — HTTP/2 and Unix-socket upstream transports are not executed
- Status: fixed
- Area: Proxy
- Caddy behaviour: Proxies over h2c/h2 upstreams, Unix sockets, FastCGI and other transports configured in `transport`.
- caddy-rs behaviour: h2c/h2 upstreams and Unix-socket upstreams are implemented and forwarded by `reverse_proxy` (`transport.versions`, `dial: "unix/..."`); unsupported transport variants still fail loudly.
- Rationale: Adapter parity and runtime honesty are separate claims. Rejecting a transport at build time is loud; silently downgrading to HTTP/1.1 over a Unix socket would be a real behavioural defect.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/client.rs` (h2c and Unix-socket clients), `crates/proxy/src/handler.rs` upstream transport tests.

## DIV-0028 — ACME account keys support certmagic's ECDSA/RSA key types
- Status: fixed
- Area: TLS
- Caddy behaviour: certmagic generates an ECDSA P-256 account key by default but loads RSA, P-384 and SEC1/PKCS#1 `account_key` PEMs and selects the matching JWS algorithm.
- caddy-rs behaviour: `account_key` accepts ECDSA P-256 (ES256), ECDSA P-384 (ES384) and RSA 2048/4096 (RS256) in certmagic's SEC1 `EC PRIVATE KEY`, PKCS#1 `RSA PRIVATE KEY` or PKCS#8 `PRIVATE KEY` encodings; the JWS `alg`, JWK and RFC 7638 thumbprint (and therefore external-account bindings) follow the loaded key. New account keys are still generated as ECDSA P-256/ES256 like certmagic and persisted as certmagic-compatible SEC1 (or PKCS#1 for RSA); legacy PKCS#8 keys remain readable. Ed25519 account keys, unknown labels/types and RSA sizes other than 2048/4096 fail with located `AcmeError::AccountKey` errors.
- Rationale: parity for certmagic's loadable account-key surface; the cached `rsa` crate supplies RS256 signing, and unsupported key types stay loud.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/acme/mod.rs` (`account_key_generates_and_round_trips_certmagic_pem`, `account_keys_support_certmagic_key_types_and_pem_encodings`, `account_key_rsa4096_fixture_loads_and_signs`, `mock_transport_accepts_es384_and_rs256_account_keys`, `configured_p384_and_rsa_account_keys_take_precedence`).

## DIV-0029 — ACME account storage shape is caddy-rs-specific
- Status: accepted
- Area: TLS
- Caddy behaviour: certmagic stores ACME account data (registration/orders) under the configured storage with certmagic's own JSON shape.
- caddy-rs behaviour: account registration data is persisted under the data directory in caddy-rs's own JSON shape; the account key is persisted in certmagic's SEC1/PKCS#1 PEM encoding (legacy PKCS#8 still loads) while the account JSON remains caddy-rs-shaped, not byte-compatible. Storage module selection and the on-disk certificate layout are Caddy-compatible (DIV-0029 scope is only the account metadata file).
- Rationale: the account file is internal installer state, not an operator-facing contract; sharing it byte-for-byte with certmagic is not required for the compatibility promise.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/acme/mod.rs` account storage/round-trip tests, `crates/tls/src/storage.rs` layout/CertMagic-fixture tests, `crates/tls/src/automatic_https.rs` configured-storage persistence/reload tests, `crates/tls/src/storage.rs` layout tests.

## DIV-0030 — ACME terms acceptance and ZeroSSL EAB provisioning differ
- Status: accepted
- Area: TLS
- Caddy behaviour: certmagic prompts/accepts CA terms through an agreement callback and auto-provisions ZeroSSL EAB credentials from the configured email; CA `userActionRequired` requires operator action.
- caddy-rs behaviour: registration requires an explicit `terms_of_service_agreed` flag and otherwise fails with typed `TermsOfServiceRequired` naming the TOS URL before any request; `userActionRequired` problem documents are flagged; ZeroSSL automatic EAB is not implemented (configure `external_account`).
- Rationale: a testable loud failure instead of an implicit interactive agreement.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/acme/mod.rs` (`terms_of_service_must_be_accepted_before_any_request`, `user_action_required_problem_is_flagged`).

## DIV-0031 — ACME challenge selection is a fixed policy with no solver fallback
- Status: open
- Area: TLS
- Caddy behaviour: chooses a solver per challenge advertised by the CA and retries with another challenge type if a solver fails.
- caddy-rs behaviour: `ChallengePolicy` selects one enabled challenge (default DNS-01 > HTTP-01 > TLS-ALPN-01, overridable) and the HTTP-01/DNS-01/TLS-ALPN-01 solvers are wired into issuance, but there is no cross-challenge fallback after a solver failure (T-TLS-064).
- Rationale: deterministic selection is testable now; solver wiring is T-TLS-042/043/044.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/acme/order.rs` (`challenge_selection_respects_policy_and_preference`).

## DIV-0032 — Configured certificate key types are honoured; ed25519 and PKCS#8 encoding remain divergent
- Status: open
- Area: TLS
- Caddy behaviour: uses the configured certificate key type (`p256` default, `p384`, `rsa2048`, `rsa4096` and `ed25519`; `external/caddy/modules/caddytls/automation.go:133`, `values.go:97-103`) and certmagic stores certificate private keys as SEC1/PKCS#1 PEM; additional CSR extensions are a certmagic-library capability not exposed by Caddy's config.
- caddy-rs behaviour: `apps.tls.automation.policies[].key_type` selects p256 (default), p384, rsa2048 or rsa4096 for ACME CSR generation and for internal-CA leaf issuance. CSRs use ECDSA-SHA256, ECDSA-SHA384 or SHA256-RSA signatures; internal leaves are generated with the requested key (P-256/P-384 via ring, RSA 2048/4096 via the `rsa` crate) and signed by the local P-256 CA. Renewals preserve the key type inferred from the existing key. Unknown values fail loudly at `apps.tls.automation.policies[i].key_type`; `ed25519` is a located unsupported error because this offline build has no Ed25519 PKCS#10 signing path (it is not silently downgraded). Certificate private keys remain PKCS#8 in CSR/storage/runtime rather than certmagic's SEC1/PKCS#1, and `additional_extensions` is not implemented.
- Rationale: every key type Caddy accepts except ed25519 is generated and tested on both issuer paths; PKCS#8 is kept for rustls runtime loading and remains the documented residual divergence.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/acme/csr.rs` (`generates_csrs_for_each_supported_key_type`, `certificate_key_type_parse_is_located_and_rejects_ed25519`), `crates/tls/src/issuer.rs` (`issuance_uses_configured_csr_key_type_for_p384_and_rsa2048`), `crates/tls/src/automatic_https.rs` (`plan_parses_key_type_and_rejects_unknown_values`), `crates/tls/src/internal_ca.rs` (`issued_leaf_uses_configured_key_type`).

## DIV-0033 — ACME HTTP transport uses hyper+rustls with file-based roots, HTTP/2, proxy and timeout
- Status: open
- Area: TLS
- Caddy behaviour: certmagic uses Go net/http with system x509 roots, optional `network_proxy` (`caddy.network_proxy.url`), `acme_timeout` (`caddy.Duration`; 0 = no timeout), `trusted_roots_pem_files`, and HTTP/2-capable connections.
- caddy-rs behaviour: `HyperTransport` speaks HTTP/1.1 and HTTP/2 (ALPN `h2`/`http/1.1`) over hyper+rustls(ring), with conventional platform PEM bundles or explicit PEM-root APIs. `acme_timeout` is parsed from Caddy JSON and applied per ACME HTTP request (typed timeout; Caddy's certmagic applies `CertObtainTimeout` to the whole obtain flow, and an explicit 0 is rejected here rather than meaning "no timeout"). `network_proxy` supports the `caddy.network_proxy.url` module with an `http://host:port` forward proxy (HTTPS via CONNECT then TLS, h2-aware); https/socks5 proxies, other `from` sources and malformed URLs are located errors. Challenge servers are never proxied. The Caddyfile adapter accepts explicit `tls { issuer acme [<ca>] { ... } }` for `timeout` → `acme_timeout`, positional CA/`dir`, `email`, `disable_http_challenge`, `disable_tlsalpn_challenge`, `trusted_roots` and `eab`, golden-verified against real Caddy v2.11.9; unsupported ACME options (`preferred_chains`, `lifetime`, `profile`, `test_dir`, `distributed`, alternate ports, `dns`/propagation/resolver options) remain located errors. `network_proxy` has no Caddyfile form in Caddy v2.11.9 and remains JSON-only.
- Rationale: no native-cert/webpki-roots crates are available offline; file-based roots are exercised by loopback HTTP/S, h2-only and CONNECT-proxy tests.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/acme/transport.rs` (`https_transport_handshakes_with_explicit_trust_root`, `https_transport_rejects_untrusted_certificate`, `negotiates_http2_via_alpn`, `network_proxy_tunnels_every_https_request`, `acme_timeout_bounds_slow_requests`), `crates/tls/src/issuer.rs` config-parsing tests, `crates/config/tests/acme_issuer_adapt.rs` (explicit issuer Caddyfile golden).

## DIV-0034 — Cloudflare DNS-01 provider is interface- and mock-tested only
- Status: fixed
- Area: TLS
- Caddy behaviour: the `dns.providers.cloudflare` plugin creates/deletes challenge TXT records through the live Cloudflare v4 API and is registered as a module.
- caddy-rs behaviour: The Cloudflare provider has a live hyper-backed v4 API transport selected from `challenges.dns.provider` configuration, is registered as `dns.providers.cloudflare`, and is wired into challenge solving (offline mock/DoH tests; live validation tracked by T-COMPAT-021).
- Rationale: the provider logic and config parsing are testable offline; live transport and registry wiring belong to the ACME solver task.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/cloudflare.rs`, `crates/tls/src/dns_providers.rs` (mock API/DoH end-to-end), live validation tracked by T-COMPAT-021.

## DIV-0035 — Cloudflare cleanup and TTL edge semantics
- Status: accepted
- Area: TLS
- Caddy behaviour: a delete of an absent TXT record surfaces the provider error (cleanup failures are tolerated by certmagic); a TTL of 1-59 s is sent to the API and rejected there.
- caddy-rs behaviour: HTTP 404 / Cloudflare code 81044 on delete is treated as success (idempotent cleanup, delete-twice safe); a TTL in 1-59 s is rejected at config time with a located `DnsError::Config` naming the 0/>=60 s constraint; the in-memory test provider still returns `RecordNotFound`.
- Rationale: challenge cleanup must be retry-safe; failing early on an API-invalid TTL avoids a mid-issuance provider error.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/cloudflare.rs` (`delete_is_idempotent`, TTL validation tests).

## DIV-0036 — Server-level request-body and connection caps are caddy-rs extensions
- Status: accepted
- Area: HTTP
- Caddy behaviour: no server-level body cap (`request_body` is a per-route handler) and no `max_connections` field; strict JSON loading rejects unknown server fields.
- caddy-rs behaviour: `apps.http.servers.<name>.max_request_body_size` (bytes; 0/absent unlimited) returns 413 before routing; `max_connections` (0/absent unlimited) accepts the TCP connection then closes it when the listener cap is reached.
- Rationale: hardening before untrusted exposure; silently ignoring a cap would be unsafe.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/server/tests/http_limits.rs`.

## DIV-0037 — Read/write timeouts are per-I/O stalls, not whole-transfer deadlines
- Status: accepted
- Area: HTTP
- Caddy behaviour: `read_timeout`/`write_timeout` are single deadlines over the whole transfer; idle timeouts reset on progress.
- caddy-rs behaviour: configured read/write timeouts apply to each stalled transport operation; a peer making progress is never disconnected. When `read_timeout` is shorter than `idle_timeout`, it also bounds keep-alive waits.
- Rationale: hyper 1.x has no request/response deadline hook; per-operation timers still mitigate slowloris/stalled reads.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/server/tests/http_limits.rs` (`read_timeout_closes_stalled_request`, `idle_connection_is_closed`).

## DIV-0038 — h2c via HTTP/1.1 Upgrade is served when configured
- Status: fixed
- Area: HTTP
- Caddy behaviour: cleartext listeners accept `Upgrade: h2c` and switch the connection to HTTP/2 in addition to prior knowledge; only when the server's `protocols` include `h2c` (default protocols do not), and an h2c Upgrade offer must carry a valid `HTTP2-Settings` header (RFC 7540 §3.2.1) with no request body.
- caddy-rs behaviour: `apps.http.servers.*.protocols` is a typed field (h1/h2/h2c/h3 accepted; unknown rejected; empty rejected). A bodyless cleartext HTTP/1.1 request offering `Upgrade: h2c` receives `101 Switching Protocols` with canonical `Connection: Upgrade`/`Upgrade: h2c` headers and hyper serves HTTP/2 on the upgraded stream through the same router only when `protocols` includes `h2c`; otherwise the offer is served as ordinary HTTP/1.1 (matching Caddy's default and the real-Caddy oracle). The `HTTP2-Settings` value is now validated (missing, malformed, non-base64url, or body-bearing offers are served as HTTP/1.1), and the hyper-negotiated HTTP version is propagated on `Request::version`, so the `protocol` matcher sees the effective protocol (HTTP/2 for ALPN h2, prior-knowledge h2c and h2c-upgraded requests; HTTP/1.1 otherwise). h2c-upgraded connections receive the same Go-compatible SETTINGS as prior-knowledge h2, including `SETTINGS_ENABLE_CONNECT_PROTOCOL` only when the process runs with `GODEBUG=http2xconnect=1` (DIV-0071). Residual: h3 is served only on explicitly configured `udp/...` listeners (no automatic UDP listener creation from a TCP `listen`); see DIV-0004 for the full HTTP/3 support/gap matrix.
- Rationale: default and configured behaviour now match Caddy, including the Upgrade-request validation Caddy inherits from net/http's h2c support.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_limits.rs` (`h2c_upgrade_offer_is_served_as_http1_without_h2c_protocol`, `h2c_upgrade_without_settings_is_served_as_http1`, `h2c_upgrade_with_malformed_settings_is_served_as_http1`, `h2c_upgrade_switches_to_http2`), `crates/http/src/upgrade.rs` (`h2c_upgrade_settings_*`).

## DIV-0039 — Malformed server timeout/limit values are rejected at load time
- Status: fixed
- Area: HTTP / Core
- Caddy behaviour: malformed `apps.http.servers.*` durations and numeric limits are configuration errors (validation), not apply-time failures.
- caddy-rs behaviour: a signed Caddy duration parser (integer ns, negatives, Go strings including `d`) plus load-time validation rejects malformed `read_timeout`/`write_timeout`/`idle_timeout`/`read_header_timeout`/`read_idle_timeout`/`write_idle_timeout`/`keepalive_interval`/`keepalive_idle`, `max_header_bytes`, `max_request_body_size`, `max_connections` and `keepalive_count` with located paths; valid strings/ns/negative/`2d` forms accepted. Residual: the server apply-time parser remains (duplicate; a later cleanup can reuse the core helper).
- Rationale: fail-closed validation parity.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` load-time cases, server `http_limits` suite.

## DIV-0040 — systemd socket activation is a caddy-rs extension
- Status: accepted
- Area: HTTP / Runtime
- Caddy behaviour: Caddy has no socket activation; it binds configured listeners itself and fails with EADDRINUSE behind a systemd `.socket` unit.
- caddy-rs behaviour: on first apply, `LISTEN_PID` must match the process and `LISTEN_FDS` descriptors are inspected/mapped to configured listeners by network and address; matched TCP/Unix sockets are served without rebinding, unmatched configured listeners bind normally, and unclaimed inherited sockets/malformed env/count mismatches/invalid descriptors fail apply with located errors. Sockets are adopted once (later reloads bind new listeners; removed activated listeners are closed, not returned). The admin listener is never activated.
- Rationale: lets systemd own privileged ports and preserve listening sockets across restarts.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/server/src/activation.rs` and `crates/server/tests/http_socket_activation.rs`.

## DIV-0041 — retry_match response matching uses a caddy-rs `status` matcher
- Status: open
- Area: Proxy
- Caddy behaviour: response retries are driven by expression matchers over response placeholders; request matchers gate transport retries.
- caddy-rs behaviour: matcher sets containing a new `status` matcher (exact code, `Nxx` class, ranges, negation) retry matching responses; sets without it never retry responses; request-only sets gate transport retries; dial errors are retried within budget. Expression matchers are rejected loudly (`T-ROUTE-004`).
- Rationale: a small declarative status matcher covers the practical response-retry cases until the expression engine exists.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/proxy/src/retry.rs` and `crates/proxy/src/handler.rs`.

## DIV-0042 — Proxied requests carry the upstream `Via` header
- Status: fixed
- Area: Proxy
- Caddy behaviour: adds `Via: <client-protocol> Caddy` to requests sent upstream; responses gain a `Via` header.
- caddy-rs behaviour: the request-side `Via` is appended after hop-by-hop handling and before `header_up` operations, preserving any client-supplied `Via`; the client protocol comes from the `http.request.proto` request variable with a documented `1.1` fallback until the server supplies the negotiated version. Response `Via` is unchanged.
- Rationale: Caddy-compatible request metadata; server protocol wiring is tracked separately.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/handler.rs` Via tests.

## DIV-0043 — Server-level `trusted_proxies` is propagated to handlers
- Status: fixed
- Area: Proxy / Server
- Caddy behaviour: `apps.http.servers.<name>.trusted_proxies` (plus `trusted_proxies_strict`, `trusted_proxies_unix`, `client_ip_headers`) establishes the trusted-proxy context for every handler on that server: the server derives `trusted_proxy`/`client_ip` before routing, `reverse_proxy`/`forward_auth` use it for `X-Forwarded-*` and client-IP selection, and the effective client IP is available through request variables.
- caddy-rs behaviour: the runtime parses the server fields with the Caddy-compatible `caddy_rs_proxy::trusted_proxies::ServerTrustedProxies` (`http.ip_sources.static` source/ranges including `private_ranges`/`none`/`all`; strict/Unix/client-IP-header fields), validates it during apply (located errors for malformed fields and unknown sources, tracking `TRUSTED-PROXIES-SOURCE`), carries it through the listener request context and applies it to every request before router dispatch, matching Caddy's `PrepareRequest`/`determineTrustedProxy` semantics: `client_ip` is the first valid header value left-to-right by default, the right-to-left first value outside the trusted ranges with `trusted_proxies_strict`, with peer fallback and Unix-peer trust. `reverse_proxy`/`forward_auth` consume the derived variables for `X-Forwarded-For`/`Proto`/`Host` (prior chain plus peer when trusted, peer only otherwise) and for `client_ip_hash`; a handler-level `trusted_proxies` is unioned with the server decision (it can widen trust but not narrow it, exactly Caddy's precedence); `{http.vars.client_ip}` expands for header/rewrite/placeholder consumers. `http.request.remote` remains the transport peer address, as in Caddy. The `reverse_proxy` request-header and `handle_response` templates also expand `{http.request.hostport}`, `{http.request.port}`, `{http.request.remote}`, `{http.request.remote.host}` and `{http.request.remote.port}`; `{http.request.host}` excludes the port; `http.request.remote.*` stays the transport peer, as in Caddy (`{http.request.client_ip}` is not a Caddy placeholder — the resolved IP is the `client_ip` variable). Trusted Unix peers keep prior `X-Forwarded-*` values without appending a peer; untrusted Unix peers strip them (Caddy's `RemoteAddr == "@"` branch). Access-log `request.client_ip` is resolved with the same policy (`T-ADMIN-037`): peer for untrusted clients, the configured `client_ip_headers` bare IP for trusted proxies, `""` for untrusted Unix peers; `remote_ip`/`remote_port` remain the transport peer (Unix peers log `remote_ip:"@"`). The Caddyfile `servers { trusted_proxies ... }` / `client_ip_headers` emission is implemented and golden-verified against real Caddy v2.11.9 (`T-CONF-051`). caddy-rs also emits load-time warnings (Caddy is silent) when a range trusts every address (`all`/`0.0.0.0/0`/`::/0`) or when `proxy_protocol` runs on an exposed listener, naming the server and the range/listener (`T-TLS-087`).
- Rationale: server-level context is now the single source of client-IP trust for handlers and matches Caddy's derivation and precedence; remaining gaps are adapter emission and access-log plumbing.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_trusted_proxies.rs`, `crates/server/tests/http_client_ip_logs.rs`, `crates/proxy/tests/trusted_proxy_forwarding.rs` (7 real-listener forwarded-header/placeholder cases), `crates/proxy/src/template.rs` (address-placeholder expansion) (9 real-listener cases: trusted/untrusted, strict/default, header ordering, handler-level widening and non-narrowing, IPv6, located unknown-source error), `crates/proxy/src/trusted_proxies.rs` unit tests, `crates/proxy/src/handler.rs` forward_auth context test, `crates/server/src/runtime.rs` `forwarded_trust_warning_tests` (permissive and explicit-/0 range warnings, exposed-listener classification, PROXY-wrapper warnings).

## DIV-0044 — Passive health state is per-handler and rotation filters available upstreams
- Status: accepted
- Area: Proxy
- Caddy behaviour: passive failure counts live in a shared usage pool keyed by dial (shared across handlers and preserved across reloads); selection filters inside the balancing policy.
- caddy-rs behaviour: each reverse_proxy handler owns its passive state, which resets on reload; unavailable upstreams are pre-filtered before the balancing policy runs, so round-robin's index is over the available subset. Distribution remains round-robin.
- Rationale: per-generation state is simpler and correctly scoped to a configuration generation; no global registry of upstream health is needed yet.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/proxy/src/passive.rs` and `crates/proxy/src/handler.rs`.

## DIV-0045 — Missing Caddyfile environment variables produce a warning
- Status: accepted
- Area: Caddyfile
- Caddy behaviour: substitutes an empty string silently for a missing `{$ENV}` with no default.
- caddy-rs behaviour: substitutes the same empty string so adapted JSON is identical, and emits a non-fatal warning through `GlobalOptions.warnings`/`AdaptedConfig.warnings` (CLI prints `warning: ...`).
- Rationale: catches typo'd environment variables without changing emitted configuration.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/config/src/parser.rs` (`missing_env_var_warns_through_the_public_parse_result`) and `crates/config/tests/heredoc_env.rs`.

## DIV-0046 — Caddyfile block nesting depth is bounded at 128
- Status: accepted
- Area: Caddyfile
- Caddy behaviour: no explicit nesting limit; deep nesting parses until the growable goroutine stack or memory is exhausted.
- caddy-rs behaviour: more than 128 nested braced blocks returns a located `ParseError` naming the line and limit; sibling blocks reset the depth. A former ~2.5 KB stack-overflow reproducer now yields that error.
- Rationale: fixed Rust stacks made unbounded recursion an uncatchable abort and a potential DoS once `/adapt` is exposed; 128 is far above real configurations.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/config/src/parser.rs` (depth tests) and `crates/config/tests/adapter_fuzz.rs`.

## DIV-0047 — Caddyfile file/glob imports resolve relative to the importing file
- Status: fixed
- Area: Caddyfile
- Caddy behaviour: imports resolve relative to the importing file's directory and diagnostics report the origin file/line.
- caddy-rs behaviour: file and glob imports now resolve relative to the importing file (including nested imports and globs inside imported files); imported tokens carry their filename so parser and adapter diagnostics report `sub/extra.caddyfile:3`; missing imports name the importing file:line. Residual: displayed paths are relative to the root Caddyfile directory and the stdin path refuses file imports loudly.
- Rationale: nested import trees and actionable diagnostics match Caddy.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/imports_files.rs` (8 tests).

## DIV-0048 — Admin partial-update error status mapping differs
- Status: accepted
- Area: Admin
- Caddy behaviour: malformed update bodies, traversal/index errors and some decode failures surface as 500; `/load` JSON/content-type/duplicate-`@id` errors are 400; 404/409 key conflicts are 404/409.
- caddy-rs behaviour: malformed JSON bodies, traversal/index errors, decode failures and full-config validation failures all return 400 with the reason; key insert/replace conflicts match Caddy's 409/404.
- Rationale: 400 for client-supplied invalid input is clearer and consistent; tracked in case tooling depends on Caddy's exact codes.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/admin/src/lib.rs` (partial-update error tests).

## DIV-0049 — Admin config ETags match Caddy; residual preconditions are extensions
- Status: mitigated
- Area: Admin
- Caddy behaviour: config responses carry a strong ETag `"<path> <16 hex>"` (xxHash64); updates honour `If-Match`; `Cache-Control: must-revalidate`; unchanged-config updates can be short-circuited; Caddy ignores `If-None-Match`.
- caddy-rs behaviour: matching strong ETag format/algorithm (xxHash64 over the exact served bytes), `If-Match` 200/412 and exact malformed-header 400 messages are implemented and oracle-verified, and the served config body is now byte-identical to Caddy's `encoding/json` output (recursively sorted compact JSON + trailing newline), so the oracle observes identical bodies, ETags and Content-Length for config reads and post-update reads. caddy-rs additionally implements `If-None-Match` (304 on reads, 412 on writes) as a documented extension; a config normalized differently by the core model than Caddy's raw JSON could still hash/serialize differently; unchanged-config short-circuit and `must-revalidate` behaviour are not implemented.
- Rationale: format/algorithm/serialization parity is oracle-verified; the extension is additive and the remaining items are performance/management niceties.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/lib.rs` (xxHash64 vectors, ETag stability, 304/412 tests, `config_read_serialization_matches_go_encoding_json_bytes`) and the real-Caddy runtime oracle (no admin allowlist entries).

## DIV-0050 — Admin origin enforcement is simplified
- Status: open
- Area: Admin
- Caddy behaviour: origin policy distinguishes `origins` absent (derive loopback defaults) from an explicit empty list, and emits full CORS preflight headers.
- caddy-rs behaviour: core `AdminConfig` cannot distinguish absent from empty (`Vec`), both derive loopback defaults; unix listeners have no implicit origins; wildcard hosts are treated as loopback; policy is re-evaluated per request from the active generation (server may pin it); percent-encoded path segments are not decoded; only `Access-Control-Allow-Origin` is echoed (no OPTIONS allow-methods/headers/credentials).
- Rationale: loopback-by-default plus explicit enforcement covers the operational cases; exact Caddy policy nuance is tracked.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/admin/src/origin.rs` and admin tests.

## DIV-0051 — Certificate metadata JSON is a `sans`-only subset
- Status: fixed (residuals noted below)
- Area: TLS / storage
- Caddy behaviour: CertMagic persists a full `CertificateResource` document next to
  `<name>.crt`/`<name>.key` (`certmagic/certmagic.go:401-419`), marshalled with
  `json.MarshalIndent(cert, "", "\t")` (`certmagic/crypto.go:147-149`): `sans` (omitted when
  empty); `issuer_data`, which is always present because it is
  `json.Marshal(issuedCert.Metadata)` (`certmagic/config.go:784-791`) — `null` for issuers with no
  metadata (the internal CA) and acmez's `acme.Certificate` object otherwise (`url`, `ca`,
  `account`, `renewal_info`); and, inside `renewal_info`, the ARI fields `suggestedWindow`
  (`start`/`end`), `explanationURL`, `_uniqueIdentifier`, `_retryAfter` and `_selectedTime`
  (`mholt/acmez/v3/acme/certificate.go:34-64`, `ari.go:40-89`).
- caddy-rs behaviour: `FileStorage` and the S3 backend (same serializer) read and write that
  document byte-for-byte: Go field order at every level, tab indentation, no trailing newline,
  `sans` omitted only when empty, `issuer_data` always present (`null` when the issuer supplied no
  metadata), unknown fields preserved at the top level and inside `issuer_data`, `renewal_info`
  and `suggestedWindow`. A genuine Caddy v2.11.9 ACME document carrying ARI round-trips unchanged,
  and the internal-CA document above is reproduced exactly. A missing or partial `.json` still
  loads with the documented defaults (directory name for SANs, no issuer data, no extra fields)
  and is re-created in Caddy shape on rewrite. Residual: caddy-rs does not synthesise ARI at
  issuance — its ACME issuer currently supplies `url`/`ca`/`account`, and any `renewal_info`
  supplied by an issuer is preserved; Caddy additionally queries ARI and persists the result.
- Rationale: the storage contract is now byte-compatible, so a real Caddy data directory can be
  used in either direction without losing metadata. ARI generation is issuance logic (it needs the
  ACME directory and a network round trip), not a serialisation difference, and stays a separately
  tracked residual.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/storage.rs`
  (`writes_full_certmagic_certificate_resource_and_preserves_unknown_fields`,
  `writes_null_issuer_data_for_issuers_without_metadata_like_caddy`,
  `missing_certificate_metadata_loads_documented_defaults`,
  `partial_certificate_metadata_loads_documented_defaults`,
  `certmagic_certificate_metadata_fixture_round_trips_unchanged`) and
  `caddy-rs/crates/tls/tests/caddy_storage.rs`
  (`real_caddy_acme_metadata_round_trips_byte_for_byte`, fixture
  `127.0.0.1-14000-dir/acme-metadata.pebble.test`).

## DIV-0052 — Metrics surface is a caddy-rs registry with extensions
- Status: mitigated
- Area: Observability
- Caddy behaviour: Caddy publishes HTTP metrics only when `apps.http.metrics` is enabled, optionally per-host/OTLP; it has no proxy-upstream or certificate series.
- caddy-rs behaviour: `/metrics` returns 200 text/plain from a hand-written registry always (no `apps.http.metrics` switch), with `caddy_http_*` names and caddy-rs `caddy_rs_proxy_*`/`caddy_rs_tls_*` extensions; the runtime now increments request counters/in-flight/duration/size series, handler labels are empty, request_size is declared Content-Length (0 when chunked), and proxy/certificate series are populated only where hooks exist.
- Rationale: deterministic offline registry without the `prometheus` crate; configuration modelling is a follow-up.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_observability.rs`, `crates/admin/src/metrics.rs`.

## DIV-0053 — Logging include/exclude validation
- Status: fixed
- Area: Admin / configuration validation
- Caddy behaviour: `CustomLog.provision` (`external/caddy/logging.go:495-519`) rejects a log whose `include` and `exclude` lists intersect, and (when both are populated) rejects any include entry that is not a parent or child namespace (dot-boundary prefix) of at least one exclude entry; Caddy's `validate` command reports the failure and exits non-zero. It also uses longest-namespace-prefix matching (`logging.go:535-601`).
- caddy-rs behaviour: `crates/admin/src/logging_config.rs` implements the same rules (`validate_logger_filters`, `logger_allowed`), and the CLI `validate` path provisions the access-log sinks (`ServerRuntime::validate_provisioning` -> `access_log_for` -> `LoggingConfig::from_config`), so the adapted `global_options_log_and_site.caddyfiletest` JSON is rejected with a located error naming the exact include entry (`logging.logs.default.include[0]`) and the conflicting exclude rules; compatible parent/child permutations validate. `LoggingConfig::validate_config(&Config)` is available as a validation-only hook.
- Rationale: Caddy-incompatible filter combinations are contradictions that must fail validation, not silently drop logs.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/logging_config.rs` (`adapted_global_options_log_and_site_fixture_is_rejected_like_caddy`, `compatible_include_exclude_nesting_permutations_validate`, existing `include_exclude_contradictions_are_rejected`/`logger_prefix_semantics_match_caddy`); oracle fixture evidence `.scratch/logs/w20-fixture/`.

## DIV-0054 — Listener TLS policy is explicit and certificates must be pre-loaded
- Status: open
- Area: TLS
- Caddy behaviour: TLS connection policies apply per policy/site and certificates may be automated, loaded from storage, or managed by certmagic.
- caddy-rs behaviour: TLS is enabled per listener when the HTTP server has non-empty `tls_connection_policies` or the port is the effective HTTPS port; the listener requires an `apps.tls.certificates` resolver. A TLS listener without certificates fails apply with a located error (never a cleartext downgrade). Certificate loading supports `load_pem`/`load_files` plus resolver APIs for cache/storage, but storage/cache are not wired from configuration.
- Rationale: refusing a TLS listener without certificates is the honest alternative to downgrading; apply-time failure is testable.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/server/tests/http_tls.rs` (`tls_listener_without_certificates_fails_loudly`, `certificates_alone_do_not_force_tls_on_an_http_listener`).

## DIV-0055 — On-demand TLS permission validation
- Status: fixed
- Area: Core configuration validation / TLS
- Caddy behaviour: during provisioning, `AutomationPolicy.makeCertMagicConfig` (`external/caddy/modules/caddytls/automation.go:294-311`) rejects an `on_demand` automation policy whose subjects are the default (none) or wildcard, with no permission protection, unless the policy is exempt: bounded explicit non-wildcard subjects, a single internal issuer, or explicitly configured `get_certificate` managers. Protection is an app-level `apps.tls.automation.on_demand.permission` module (`tls.permission.*`) or the deprecated `ask` endpoint (converted to the HTTP permission module, `modules/caddytls/tls.go:283-300,327-338`). Error: `on-demand TLS cannot be enabled without a permission module to prevent abuse; please refer to documentation for details`.
- caddy-rs behaviour: `crates/core/src/validate.rs` implements the same check with the same exemptions and wording, producing a located validation error at `apps.tls.automation.policies[<i>].on_demand` (Caddy reports it at provision time; both reject the adapted `tls_automation_policies_5.caddyfiletest` JSON, classified pass_error in the oracle).
- Rationale: prevents abusive on-demand issuance for unbounded hostnames.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`adapted_tls_automation_policies_fixture_rejects_on_demand_without_permission`, `on_demand_with_permission_module_or_bounded_scope_validates`, `wildcard_subject_with_public_issuer_still_requires_permission`, existing `rejects_unknown_on_demand_permission_module`); oracle evidence `.scratch/logs/w21-admin-oracle-validate.json` (known divergences: []).

## DIV-0056 — TLS-ALPN-01 is implemented and wired into automatic-HTTPS listeners
- Status: fixed
- Area: TLS
- Caddy behaviour: Serves the `acme-tls/1` ALPN protocol with a challenge certificate during validation.
- caddy-rs behaviour: `crates/tls` implements RFC 8737 challenge certificates, the `TlsAlpn01Solver` and the `AcmeTlsAlpnResolver` overlay; when automatic HTTPS is active the server advertises `acme-tls/1` on TLS listeners and selects challenge certificates only for that ALPN, delegating all other handshakes to the normal resolver. HTTP-01 remains preferred when both are available.
- Rationale: parity with Caddy's primary challenge options.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/tls_alpn.rs`, `crates/server/tests/http_auto_https.rs` TLS-ALPN fake-CA tests.

## DIV-0057 — ACME challenge preference, provider wiring and chain selection are limited
- Status: open
- Area: TLS
- Caddy behaviour: certmagic selects challenges with fallbacks, constructs DNS provider modules from `challenges.dns.provider`, can try alternate challenge types after failure, applies preferred chains and ARI/renewal-info, and retries test CAs.
- caddy-rs behaviour: DNS-01 is selected only when a provider object is configured, otherwise HTTP-01 then TLS-ALPN-01; the provider registry constructs providers from `challenges.dns.provider`. Residual gaps: no cross-challenge fallback, `preferred_chains`/`test_ca` fallback/ARI are not applied, and cleanup errors are swallowed (T-TLS-064). Challenge evidence is withdrawn on success and failure.
- Rationale: the issuance path is testable and honest; provider construction and policy refinements are follow-ups.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/tls/src/issuer.rs` and `crates/tls/src/solver.rs` (issuance, DNS-01, cleanup, policy).

## DIV-0058 — forward_auth/basic_auth handler ids differ from Caddy's adapted JSON
- Status: open
- Area: HTTP handlers
- Caddy behaviour: The Caddyfile `forward_auth` directive adapts to a configured `reverse_proxy` with rewrite/handle_response; `basic_auth` adapts to the `authentication` handler with provider `http_basic`. There is no runtime `forward_auth`/`basic_auth` module id.
- caddy-rs behaviour: The Caddyfile `forward_auth` directive adapts to Caddy's canonical `reverse_proxy`/`rewrite`/`handle_response` expansion and executes end to end (DIV-0061 fixed); `basic_auth` Caddyfile adaptation is still rejected (T-CONF-031). Both caddy-rs handler modules remain registered as an extension.
- Rationale: modelling forward_auth as a first-class handler is simpler than Caddy's reverse_proxy adaptation and keeps the auth semantics explicit; a canonical adapter mapping is tracked.
- Tracking: T-COMPAT-003
- Test: `caddy-rs/crates/http/src/auth.rs` and router integration tests.

## DIV-0059 — basic_auth verifies bcrypt and argon2id; hashes are validated at load
- Status: fixed
- Area: HTTP handlers
- Caddy behaviour: `basic_auth`/`authentication` verifies bcrypt or argon2id password hashes (or other configured hash modules). bcrypt accepts Go's modular-crypt forms and truncates passwords at 72 bytes; argon2id hashes are PHC strings (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<key>`) parsed with Caddy's `DecodeHash` (strict raw standard base64, parameters in m,t,p order). Wrong credentials produce a 401 challenge; unknown usernames are verified against fixed fake hashes to avoid timing side channels. Malformed hashes surface as a provider error for that request (401), not as a load failure.
- caddy-rs behaviour: bcrypt `$2a$`/`$2b$`/`$2x$`/`$2y$` hashes (cost 4..=31) are verified natively with the `bcrypt` crate (constant-time digest comparison; Go-compatible 72-byte truncation), and argon2id PHC strings are parsed exactly like Caddy's `DecodeHash` and verified with the `argon2` crate using the salt/parameters/key encoded in the hash and a constant-time key comparison. Unknown usernames verify Caddy's fixed fake bcrypt/argon2id hashes; wrong, empty and unicode passwords yield a plain 401; success sets `http.auth.user.id`. Both modular-crypt hashes (with the `$` prefix) and legacy base64-encoded hashes are accepted. Malformed, truncated or unsupported hashes and clear-text account passwords are rejected as located configuration errors at load (stricter than Caddy, intentionally). The JSON/Caddyfile surface is unchanged and the opt-in `plaintext` extension is unchanged. The registry does not expose `http.authentication.hashes.bcrypt`/`argon2id` as separate module entries (the algorithms are selected by the `hash.algorithm` string inside the provider), so the generated module inventory still marks those Caddy hash modules unimplemented even though both algorithms are verified natively.
- Rationale: the native crates close the offline hashing gap; validating account hashes at load turns bad auth configuration into deploy-time failures instead of per-request 401s. Constant-time comparisons and fake-hash verification for unknown users keep the failure path free of obvious timing side channels.
- Residual divergences: Caddy's Go bcrypt accepts non-standard minor versions (`$2$`, `$2c$`) that caddy-rs rejects as malformed; Caddy's Go argon2 accepts parameter combinations the Rust backend rejects at load (e.g. m<8). bcrypt/argon2id digest comparison is constant-time in both.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/auth.rs` (bcrypt cost-10 vectors across all supported versions, oracle-captured cost-4 bcrypt and argon2id m/t/p vectors, Caddy 72-byte truncation, wrong/empty/unicode/unknown credentials, canonical `authentication` JSON, legacy base64 hashes, located malformed/truncated/unsupported/clear-text errors, coarse password-length timing test) and the real-Caddy comparison in `.scratch/logs/w16-auth-oracle/comparison.txt`.

## DIV-0060 — Automatic-HTTPS applies start listeners before certificate provisioning
- Status: accepted
- Area: TLS / Runtime
- Caddy behaviour: Listeners start and TLS configuration is rotated in place; certmagic obtains certificates asynchronously so normal handshakes keep using the current resolver while challenges run.
- caddy-rs behaviour: Apply binds and starts challenge-capable listeners first (TLS listeners advertise `acme-tls/1` with the challenge overlay and manual certs as fallback; cleartext listeners answer HTTP-01/redirects), provisions synchronously, then publishes final resolver states. On first enabling automatic HTTPS or a reload that changes TLS listeners, existing TLS listeners are briefly served by bootstrap states, so normal handshakes can fail during that window; on failure the previous generation's states/listeners are restored.
- Rationale: synchronous issuance needs live listeners for real challenge validation; the window is bounded and steady state is unaffected.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_auto_https.rs` (TLS-ALPN challenge, rollback).

## DIV-0061 — shutdown_delay / grace-period edge semantics
- Status: mitigated
- Area: Server
- Caddy behaviour: `shutdown_delay` applies only when a listener is actually closing (and not shared with the new config: `ListenerUsage(addr) < 2`); `grace_period` zero means eternal; the grace-period context bounds graceful drain even during a reload (shutdown goroutines continue after the reload returns); process exit waits for earlier servers' shutdowns; a second signal force-quits.
- caddy-rs behaviour: the delay is honoured for process stop and for listeners removed by a reload; the grace timer force-closes a closing listener's connections when it expires; an absent grace period is eternal for ordinary connections; hijacked connections are excluded from the eternal wait. caddy-rs reuses listeners by configured address key, so it does not implement Caddy's cross-config shared-listener check; every removed listener gets the delay. Retired reload shutdowns are not joined at process exit beyond their own grace timers.
- Rationale: the observable reload/stop semantics (delay, drain bound, forced closure, no leaked listener) match; the missing shared-listener accounting is a narrow reload optimisation/edge case.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_graceful_shutdown.rs` (see DIV-0020), `http_cutover_rollback`, `http3`, `http_observability`.

## DIV-0062 — Internal CA is behaviour-compatible; apps.pki is mapped, trust/rotation remain narrower (mitigated)
- Status: mitigated
- Area: TLS
- Caddy behaviour: `tls internal`/`local_certs` are governed by `apps.pki` (CA id, lifetimes, install_trust), Caddy serves `/pki` endpoints and can install the root into OS trust stores; local leaves renew automatically.
- caddy-rs behaviour: `apps.pki` is a typed, validated model (`certificate_authorities`, per-CA root/intermediate, lifetimes, maintenance/renewal ratios, storage) and internal issuers are validated against it (DIV-0070); internal automation policies issue/persist/serve ECDSA P-256 local-CA leaves with Caddy's default lifetimes and storage layout, `/pki` read-only endpoints and `pki`/`trust` CLI exist (DIV-0073), and the renewal scheduler renews internal leaves. Still narrower: automatic OS `install_trust`, Firefox/Java stores, caInfo app-name reporting and root rotation are follow-ups (DIV-0073); certificates omit smallstep-specific extensions.
- Rationale: config mapping and validation are delivered; trust installation/rotation are a separate operator surface bounded by DIV-0073.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` + `crates/config/tests/pki.rs` (apps.pki), `crates/tls/src/internal_ca.rs`, `crates/tls/src/automatic_https.rs` internal-CA tests, `crates/admin/src/pki.rs`.

## DIV-0063 — Internal CA maintenance is lazy, not a background task
- Status: accepted
- Area: TLS
- Caddy behaviour: smallstep maintains CA material in the background and rotates intermediates/roots on schedule.
- caddy-rs behaviour: the intermediate is rotated lazily when the CA is loaded (at 20% lifetime remaining), the root is kept, leaves are renewed by the renewal scheduler, and an expired root fails loudly requiring manual removal. No background CA maintenance task.
- Rationale: lazy rotation avoids serving expired material without an extra scheduler.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/internal_ca.rs` lifetime/rotation tests.

## DIV-0064 — ARI and the shared certificate cache are implemented; on-demand/OCSP remain absent
- Status: open
- Area: TLS
- Caddy behaviour: certmagic uses ARI/OCSP-driven renewal timing, on-demand TLS with a permission module, and a certificate cache shared across configuration generations.
- caddy-rs behaviour: automatic HTTPS schedules validity-based renewal with ARI and a deterministic fallback (see DIV-0012). The runtime retains the active generation's `SharedCertificateStore` and hands it to the next generation's provisioner, so a reload seeds the new resolver and renewal scheduler from the certificates that are still running instead of re-issuing them (verified with a reload after deleting persisted storage while the fake CA rejects new orders); resolver hot-swap keeps in-flight handshakes on the previous `Arc`. OCSP-driven renewal, on-demand TLS/permission modules and per-policy `renewal_window_ratio` mapping are not implemented, and ARI is scheduler-fetched and in-memory only.
- Rationale: ARI and the shared cache are now wired end to end and independently tested; the remaining on-demand handshake hook and OCSP are tracked separately rather than approximated.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/renewal.rs` ARI tests, `crates/tls/src/automatic_https.rs` (`shared_certificate_store_survives_generations_without_reissue`), `crates/server/tests/http_auto_https.rs` (`reload_reuses_the_previous_generations_in_memory_certificates`).

## DIV-0065 — Caddy logging JSON mapping is a strict subset (now wired to sinks)
- Status: open
- Area: Observability
- Caddy behaviour: `logging.logs[]` supports writers/encoders/rotation/filter modules.
- caddy-rs behaviour: the admin mapping supports stderr/stdout/discard/file writers, json/filter-json, level, sampling, include/exclude, delete/replace header filters; the server builds sinks from it at startup/reload and emits/flushes/closes them. Unsupported writers/encoders/filters and `logging.sink`/core/caller/stacktrace fail loudly with located errors and `T-ADMIN-025`; rotation is not implemented (operators rotate externally).
- Rationale: honest subset, runtime wiring added in T-ADMIN-024.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/logging_config.rs`, `crates/server/tests/http_observability.rs`.

## DIV-0066 — TLS-ALPN-01 challenge certificate matches acmez's profile
- Status: fixed
- Area: TLS
- Caddy behaviour: acmez generates an ephemeral challenge certificate signed by a fresh ECDSA P-256 key, with subject CN "ACME challenge", a random 128-bit serial, notBefore now and notAfter +365 days, serverAuth EKU, basicConstraints CA:FALSE, SAN dNSName or iPAddress, and the critical id-pe-acmeIdentifier SHA-256 digest.
- caddy-rs behaviour: challenge certificates match that profile (ECDSA P-256, CN "ACME challenge", random 128-bit serial, now -> +365 days validity, serverAuth EKU, CA:FALSE, dNSName/iPAddress SAN, critical id-pe-acmeIdentifier); challenge-solver fallback and preference order remain tracked by DIV-0031.
- Rationale: parity for the RFC 8737 certificate profile; solver strategy is a separate divergence.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/tls_alpn.rs` (`challenge_certificate_matches_acmez_profile`, `challenge_certificate_is_self_signed_and_valid`).

## DIV-0067 — Dynamic upstream discovery: srv/a/multi implemented; a few runtime knobs remain open
- Status: open
- Area: Proxy
- Caddy behaviour: `dynamic_upstreams` (`http.reverse_proxy.upstreams.*`) sources are consulted on every proxy-loop iteration; a successful lookup replaces the static pool (even when it returns no upstreams), lookup errors fall back to the static pool, and retries reset caching sources. Built-ins: `srv` (service/proto/name or bare name, refresh default 1m, `grace_period`, resolver/dial_timeout/dial_fallback_delay, `dial_network`; RFC 2782 priority/weight ordering), `a` (name, port default 80, refresh, resolver, versions ip4/ip6/ip), `multi` (sources queried in order, results appended, per-source errors logged and skipped — no deduplication). Provisioned dynamic hosts keep counters/health state and appear in `GET /reverse_proxy/upstreams`; active health checks run only against the static pool, so dynamic upstreams are never actively checked (`upstreams.go`, `reverseproxy.go` 632-660, `admin.go` 124-133; Caddyfile `dynamic <source>` at `caddyfile.go` 249-267).
- caddy-rs behaviour: implements the three sources behind a `DynamicUpstreamSource` trait with an injectable `DnsResolver`; a minimal RFC 1035 client handles A/AAAA/SRV over UDP with TCP fallback, CNAME following, bounded lookups, per-key refresh caches (bounded at Caddy's 100 keys), SRV grace-period last-known-good, custom resolver addresses (IP literals) and RFC 2782 ordering. Handler integration matches Caddy: per-iteration source consultation, retry cache reset, successful-empty replaces the static pool (503 with a located log when nothing resolves), lookup errors fall back to the static pool; discovered addresses are stable `Arc<Upstream>` states so counters, active/passive health and admin statuses persist; `with_dynamic_source` allows embedding custom sources. Loud/documented gaps: SRV `dial_network` tcp4/tcp6 (`DYNAMIC-UPSTREAM-DIAL-NETWORK`), non-zero `dial_fallback_delay` (`DYNAMIC-UPSTREAM-FALLBACK-DELAY`), hostname resolver addresses (IP literals only), unknown source modules (`DYNAMIC-UPSTREAM-SOURCE`), and `max_answers` (not a Caddy v2.11.9 field; unknown-field error). Active health checks with dynamic upstreams are rejected loudly (`PROXY-DYNAMIC-UPSTREAM-HEALTH`) because Caddy would check only the static pool. Caddyfile `reverse_proxy { dynamic ... }` emission is implemented (`crates/config`, T-CONF-052): `srv` (service/proto/name/refresh/grace_period/resolvers/dial_timeout/dial_fallback_delay), `a` (name/port/refresh/resolvers/dial_timeout/dial_fallback_delay/versions) and nested `multi` emit Caddy v2.11.9's exact `dynamic_upstreams` JSON with located errors for unknown/duplicate options; `dial_network` is rejected by Caddy's parser. Core validation accepts `dynamic_upstreams` (it no longer rejects the construct), so `caddy-rs validate` and the oracle validate phase accept these configurations.
- Rationale: runtime discovery covers SRV/A/AAAA and multi clusters with Caddy's caching/fallback semantics; remaining gaps are adapter emission plus deliberately-rejected resolver knobs, none silently approximated.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/dns.rs` (wire parsing/ordering/real UDP query), `crates/proxy/src/dynamic_upstreams.rs` (srv/a/multi caching, grace, ordering, located errors), `crates/proxy/src/handler.rs` (real-listener end-to-end, refresh, retry reset, static fallback, empty 503, admin statuses, health rejection, custom source), `crates/config/tests/reverse_proxy_dynamic.rs`, `crates/config/tests/reverse_proxy_dynamic_fixtures.rs`.

## DIV-0068 — Unhandled requests match Caddy's empty 200 response
- Status: fixed
- Area: HTTP
- Caddy behaviour: Caddy's top-level empty handler responds 200 with an empty body when no route handles the request.
- caddy-rs behaviour: the top-level router now returns Caddy's emptyHandler response (200, empty body, no response headers; server adds Content-Length: 0) for unmatched requests, while explicit handler 404s and nested subroute Continue semantics are preserved.
- Rationale: parity.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/router.rs::unmatched_requests_get_caddy_empty_200`, `explicit_handler_404_is_preserved`.

## DIV-0069 — Access-log fields are populated from the request pipeline
- Status: fixed
- Area: Observability
- Caddy behaviour: an access entry carries the complete `logRequest` field set: actual request/response byte counts (`bytes_read` from `lengthReader.Length`, `modules/caddyhttp/server.go:1598-1612`, emitted at `server.go:1309`; `size` from `responseRecorder.size`, `modules/caddyhttp/responsewriter.go:185-210`, emitted at `server.go:1312`), the authenticated `user_id` from `http.auth.user.id` (`server.go:1289-1290`; `caddyauth.go:170`, `setAuthUserPlaceholders` `:292-295`), `duration` measured after the handler chain / at last byte (`server.go:710`, `:715`), `status` (0 when nothing was written, `responsewriter.go:204`), credential-redacted `resp_headers` (`server.go:1314`; `internal/logmarshalers.go:20-35`), the write-failure-only `write_error` (`server.go:1320`) and `ExtraLogFields` extras appended after the built-ins (`logging.go:261-286`, `server.go:1321`; `uuid` `replacer.go:228`, `traceID`/`spanID` `tracing/tracer.go:111-112`, `log_append` `logging/logappend.go:158`).
- caddy-rs behaviour: `crates/admin/src/access_log.rs` models every field with Caddy's JSON key/type and always emits the mandatory ones (`user_id` is `""` when anonymous; optional fields are omitted, never `null`). The runtime now populates them (`T-ADMIN-045`): the server creates one `AccessLogContext` per request when access logging is enabled and carries it on the internal request; `basic_auth` publishes the authenticated username into `user_id` (as well as setting `http.auth.user.id`); `reverse_proxy` publishes the caddy-rs `upstream` extension (configured `dial`, resolved `remote_ip`/`remote_port` when the dial is a literal IP, time-to-response-headers `duration`, response `status`; a retried request reports the attempt whose response was served); actual request-body bytes are counted from the buffered length or from the streamed body as handlers read it; the response body is observed by the server, which counts the actual bytes written and finishes `duration` at body end rather than at headers; and `write_error` is present only when the response body yielded an error, was truncated before its advertised length, or was dropped after bytes were written (`HEAD`, `1xx`, `204`, `304` and fully-written fixed-length bodies are not failures). Entries are emitted after the response body completes. `resp_headers` is credential-redacted like the request headers (`Set-Cookie`/`Authorization`/`Proxy-Authorization`/`Cookie` → `REDACTED` unless `should_log_credentials`), and custom response-header rules apply. The proxy `upstream` object remains a caddy-rs extension (AS-09 schema): Caddy emits `upstream` only on its DEBUG "upstream roundtrip" line (`reverseproxy.go:1125-1127`), never in the access entry.
- Rationale: parity for every Caddy `logRequest` field, with actual byte counts and body-end timing instead of declared/approximate values. The transport (hyper) does not expose the underlying socket write error, so `write_error`'s text records the observable fact — the body error string, or how many bytes were written before the connection closed — rather than Go's `write tcp ...: broken pipe`; the field's presence/absence semantics match Caddy. For bodiless responses (`HEAD`, `1xx`, `204`, `304`) hyper never polls the response body, so `size` reports the actual bytes handed to the transport (0) rather than the handler-intended body length Caddy's `ResponseRecorder` would count; no `write_error` is emitted for those. `forward_auth` does not set `user_id`, matching Caddy (it copies the auth service's response headers; only credential providers set `http.auth.user.id`).
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/access_log.rs` (per-field present/absent, full representative entry, redaction, counter/timing, context sharing); `crates/http/src/body.rs` (body observer completion: bytes, end/error/drop, streamed request-body counter); `crates/http/src/auth.rs` (`basic_auth_plaintext_verifies_credentials_and_sets_identity` publishes `user_id`); `crates/proxy/src/handler.rs` (`records_upstream_attempt_in_the_access_log_context`); `crates/server/src/observability.rs` (`successful_bodies_omit_write_error`, `failed_and_truncated_bodies_record_write_error`); `crates/server/tests/http_observability.rs` (`proxied_authenticated_request_logs_user_bytes_body_duration_and_upstream`, `failed_response_write_logs_write_error`, `access_log_file_receives_entry_with_redaction`).

## DIV-0070 — Internal issuer CA references were only checked at provisioning (fixed)
- Status: fixed
- Area: TLS / Validation
- Caddy behaviour: `validate` rejects a `tls.issuance.internal` issuer that references a CA ID with no configured certificate authority (`apps.pki`), e.g. `no certificate authority configured with id: foo`.
- caddy-rs behaviour: `apps.pki` is a typed, validated part of the configuration model, and internal issuers are checked during validation: a referenced CA must exist in `apps.pki.certificate_authorities`, while the default `local` CA is accepted when the PKI app is absent or empty. The rejection is located at `apps.tls.automation.policies[i].issuers[j].ca` with Caddy's message. Caddy reports this class of rejection during provisioning and caddy-rs during validation; the oracle treats located config rejections (`parse`/`validation`/`provision`) as equivalent for the validate phase, so upstream `tls_internal_options` is `pass_error`.
- Rationale: rejecting earlier at validation is equally loud and avoids accepting a configuration that can never provision; there is no silent fallback to the default CA.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (internal issuer CA existence/default-local tests), `crates/config/tests/pki.rs` (upstream `tls_internal_options` golden fixture and `apps.pki` mapping), oracle validate probe (`tls_internal_options` is now `pass_error`).

## DIV-0071 — HTTP/2 extended CONNECT matches Caddy's GODEBUG gate
- Status: fixed
- Area: HTTP / Proxy
- Caddy behaviour: WebSocket-over-HTTP/2 (RFC 8441 extended CONNECT with `:protocol: websocket`) is supported through Go's net/http HTTP/2 server, but Go leaves `SETTINGS_ENABLE_CONNECT_PROTOCOL` unadvertised by default (Go issue #71128); Caddy therefore only enables it when the process runs with `GODEBUG=http2xconnect=1`, and only on servers whose `protocols` include h2/h2c (Caddy calls `http2.ConfigureServer` in that case; live Caddy v2.11.7 SETTINGS show no 0x8 by default). `reverse_proxy` rewrites an accepted extended CONNECT into an HTTP/1.1 WebSocket upgrade to the upstream and tunnels the h2 stream.
- caddy-rs behaviour: the server mirrors Caddy v2.11.7: hyper's h2 extended CONNECT support is enabled only when the process environment contains `GODEBUG=http2xconnect=1` (same gate for TLS/prior-knowledge h2 and h2c-upgraded connections); without it a default server neither advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` nor accepts `:protocol` (hyper rejects the stream with PROTOCOL_ERROR, like Go). With the gate on, `:method CONNECT` + `:protocol websocket` is rewritten exactly as Caddy prepares it (GET, `Upgrade: websocket`, `Connection: Upgrade`, fresh `Sec-WebSocket-Key`, Host from `:authority`) and routed through reverse_proxy's existing HTTP/1.1 WebSocket upgrade path; the upstream receives a normal HTTP/1.1 upgrade and the h2 CONNECT stream is tunnelled bidirectionally and byte-transparently with the existing `caddy_rs_proxy::websocket::tunnel`. The server answers with `200 OK` (not 101) and strips `Connection`, `Upgrade`, `Sec-WebSocket-Accept`, `Sec-WebSocket-Protocol` and `Content-Length`, like Caddy. The RFC 6455 close-frame handshake is applied to the h2 stream too (caddy-rs extension: Caddy's `isWebsocket` does not detect CONNECT requests). Plain HTTP/2 CONNECT without `:protocol`, unsupported `:protocol` values, and the websocket form while the GODEBUG gate is off are rejected loudly with 501 and an explanatory body; a missing `:authority` is rejected by HTTP/2 itself (PROTOCOL_ERROR). h3 extended CONNECT remains unimplemented; the upstream must speak HTTP/1.1 WebSocket (Caddy has the same assumption).
- Rationale: exact runtime gate and request rewriting match Caddy v2.11.7, so only the documented close-frame extension and the absent HTTP/3 variant differ; unsupported forms are rejected loudly.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http2_extended_connect.rs` (SETTINGS advertisement, prior-knowledge h2 tunnel/byte echo, h2c-upgraded tunnel, upstream-EOF close frame, ordinary h2 unaffected, loud rejects), `crates/server/tests/http2_extended_connect_disabled.rs` (default PROTOCOL_ERROR without GODEBUG), `crates/server/tests/http2_settings.rs` (no 0x8 by default).

## DIV-0072 — HTTP/2 upstream requests use the original Host as :authority
- Status: fixed
- Area: Proxy
- Caddy behaviour: the Go HTTP/2 transport sends the original request Host as `:authority` and does not add a separate Host field.
- caddy-rs behaviour: per-upstream fixed-target connectors let h2/h2c transforms build the outbound URI from the original Host (or header_up Host override) while still dialing the configured upstream and deriving SNI/trust from the dial target/server_name; the explicit Host field is removed for h2, matching Caddy. h1 keeps the previous dial-authority URI + Host header.
- Rationale: parity achieved with per-upstream connectors.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/handler.rs::h2_tests` authority/Host tests (h2, h1 fallback, unix+TLS, h2c).

## DIV-0073 — PKI app configuration, CA info names and trust-store installation
- Status: mitigated
- Area: Admin / CLI / PKI
- Caddy behaviour: `apps.pki.certificate_authorities.<id>` configures the CA name, root/intermediate CNs and material, lifetimes and `install_trust`; the PKI app provisions the default `local` CA implicitly, installs each root into the platform store plus NSS/Firefox and Java keystores (`caddypki` `installRoot`, `smallstep/truststore`, `caddy trust`), and `/pki/ca/<id>` returns `caInfo{id,name,root_common_name,intermediate_common_name,root_certificate,intermediate_certificate}` using the configured names.
- caddy-rs behaviour: `GET /pki/ca/<id>` returns Caddy's `caInfo` key set with the config-facing id and the configured `apps.pki...name` (default `Caddy Local Authority`); it stays read-only and does not lazily provision the default CA (located 404 until material exists). `caddy-rs trust` installs the root into the platform store plus every discovered NSS/Firefox database and Java keystore (via `certutil`/`keytool`), is idempotent, prints exact manual commands with `--dry-run`, reports every store it cannot update with a loud limitation naming the missing tool/platform, and honours `install_trust: false` when given `--config`. Deliberate differences: `caddy-rs trust` reads `<data-dir>/pki/authorities/<id>/root.crt` directly instead of fetching `caInfo` from the admin API; NSS/Java aliases are `caddy-rs-<ca-id>` instead of a subject-derived nickname; Windows automatic installation is not implemented (printed `certutil` instructions); `run` now defaults to Caddy's `AppDataDir()` (`$XDG_DATA_HOME/caddy`, `$HOME/.local/share/caddy`, platform variants) with a legacy `.caddy-rs` fallback, while `pki`/`trust` retain the legacy `.caddy-rs` default unless `--data-dir`/`CADDY_RS_DATA_DIR` overrides it. Deferred: TLS provisioning does not consume `apps.pki` CA configuration (extra CA ids, name-derived certificate CNs, configured root/intermediate material, lifetimes, automatic `install_trust`), so generated certificates still use the default `local` CA/`Caddy Local Authority` display name and automatic trust installation is replaced by an explicit `caddy-rs trust` run.
- Rationale: CA info and explicit trust installation are compatible and honest with loud limitations; automatic provisioning/trust wiring needs crates/tls + crates/server and is tracked separately rather than silently approximated.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/pki.rs` (configured CA name/default/data-dir tests), `crates/admin/src/trust.rs` (store planning/execution/idempotency/limitations), `crates/cli/tests/cli.rs` (`trust_*` verb tests, the `pki list/show/export` tests, and `trust_uses_the_shared_data_directory_resolution`); oracle evidence `.scratch/logs/w13-admin-oracle/{caddy-ca-info.json,caddy-rs-ca-info.json}`.

## DIV-0074 — DNS-01 provider set and propagation checking are narrower than Caddy
- Status: open
- Area: TLS / ACME
- Caddy behaviour: a plugin ecosystem of DNS providers; propagation checks use configured raw-DNS resolvers/provider logic (some providers wait on their own change APIs); DNS-only selection may fall back across challenges.
- caddy-rs behaviour: `cloudflare`, `digitalocean` and `route53` provider modules are constructible from `challenges.dns.provider` configuration and mock-tested offline (live credentials/network untested). DigitalOcean uses the v2 bearer-token API with longest-suffix `/v2/domains` discovery and TXT create/list/delete (idempotent absent deletes, token redaction). Route 53 uses SigV4 (known-vector tested), `ListHostedZonesByName`, `ChangeResourceRecordSets` UPSERT/DELETE, `ListResourceRecordSets` and `GetChange` propagation polling with a bounded timeout; credentials/region come from settings or the standard AWS environment variables. Unknown providers/options and missing credentials fail loudly with `T-TLS-063`. The Route 53 solver uses provider propagation; the other providers keep the shared DNS-over-HTTPS checker (not Caddy's configured `resolvers`, which is parsed but unused). Configuring DNS still selects DNS-01 only without cross-challenge fallback; Cloudflare TTL constraints differ. Core module inventory/Caddyfile adapter provider lists and generated module-parity docs still list only Cloudflare (follow-up outside `crates/tls`).
- Rationale: honest offline-tested subset; live DNS needs credentials, and the module registry/generated docs are owned by the config/admin wave.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/digitalocean.rs` (zone discovery, create/list/delete, idempotent delete, errors/redaction, propagation timeout), `crates/tls/src/route53.rs` (SigV4 known vector, zone discovery, change/list flow, GetChange timeout, idempotent delete, env credentials/redaction), `crates/tls/src/dns_providers.rs` (factory/registry tests).

## DIV-0075 — Request bodies stream end to end, with retry-capable buffering
- Status: fixed
- Area: HTTP / Proxy
- Caddy behaviour: streams request bodies through to upstreams (bounded by request_buffers) with retry/replay semantics and lazy request_body limits.
- caddy-rs behaviour: the HTTP engine carries `RequestBody`/streaming bodies and the server dispatches hyper `Incoming` unbuffered when the composed router capability does not require buffering; `reverse_proxy` streams bodies exactly once, buffers once for retry/try_duration/handle_response configurations and replays per attempt, maps limit failures to Caddy's empty 413 before consuming handlers, and fails loudly (502) if a retry would need an already-streamed body. Full-duplex responses-before-upload-completes remain unimplemented.
- Rationale: complete for normal and retry-capable proxy paths; full duplex is a follow-up.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/request_streaming.rs`, `crates/proxy/src/handler.rs` body tests, real-listener streaming evidence.

## DIV-0076 — WebSocket tunnel close-frame handshake
- Status: fixed
- Area: Proxy
- Caddy behaviour: an upgraded WebSocket tunnel is byte-transparent. On server shutdown Caddy's registered graceful-close handling writes a Close control frame (1001 going away, `writeCloseControl` in `modules/caddyhttp/reverseproxy/streaming.go`) to both peers before closing; Caddy v2.11.7 does not synthesise a Close frame when the upstream closes the tunnel first.
- caddy-rs behaviour: upgraded HTTP/1.1 tunnels run through `caddy_rs_proxy::websocket::tunnel`, which detects real RFC 6455 handshakes (Upgrade/Connection tokens, `Sec-WebSocket-Key` request + `Sec-WebSocket-Accept` 101 response) and writes exactly one Close control frame (2-byte status, no reason) to the client: 1001 going away written when the connection is actually closed — that is, at graceful-shutdown grace expiry (the runtime's forced-close phase) or on an immediate/forced shutdown — and also masked to the upstream, matching Caddy's `writeCloseControl`/`cleanupConnections` timing (hijacked tunnels stay alive through the grace period and get the frame at close time); and 1000 normal closure on upstream EOF, followed by a client write-half shutdown. The upstream-EOF 1000 frame is a deliberate caddy-rs extension over Caddy v2.11.7 (which synthesises only on shutdown and otherwise leaves clients with an abnormal close), so raw WebSocket clients observe a close handshake instead of 1006 in both cases. Ping/pong and all other frames remain byte-transparent, non-WebSocket upgrades never receive synthetic frames, and copy errors still close the TCP connection without a frame (same as Caddy streaming errors). Residual: the close handshake is best effort — the client's Close acknowledgement is not required and the remaining copy direction is aborted after a 5s `CLOSE_HANDSHAKE_TIMEOUT`.
- Rationale: clients and intermediaries treat an abnormal 1006 as a failure; synthesising the RFC 6455 close control frame on shutdown and on first upstream EOF gives clean teardown while preserving byte transparency for normal traffic.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/websocket.rs` (real-socket close/EOF/shutdown/ping-pong/non-WebSocket/cancellation tests), `crates/server/tests/http_websocket.rs` (upstream EOF → 1000, runtime shutdown → 1001, non-WebSocket upgrade byte-transparent).


## DIV-0077 — file matcher covers try_files, globs and `=NNN`; custom filesystems remain unsupported
- Status: open
- Area: HTTP
- Caddy behaviour: `file` matcher with root/try_files/try_policy/split_path, Go `filepath.Glob` patterns, `=NNN` error fallback, custom filesystem modules and placeholders (`modules/caddyhttp/fileserver/matcher.go`).
- caddy-rs behaviour: implements root (default `{http.vars.root}`, per-request `ReplaceAll` with Caddy's `.` empty-value fallback and Go `path.Clean`, including relative roots), try_files, all five try_policy values, split_path and the `{http.matchers.file.*}` placeholders (relative/absolute/type/remainder) with Caddy v2.11.9 path cleaning, expanded-pattern trailing-slash restoration, directory fall-through and traversal containment. `try_files` globbing covers `*`, `?`, `[...]` classes, `\` escapes, sorted existing-only results, placeholder-value glob escaping, global fallback literals (`first_exist_fallback`) and `=NNN` (100–999) errors with Caddy's digits error message. Custom `fs` modules are rejected loudly; the adapter parses the full `file { root/try_files/try_policy/split_path }` Caddyfile block and inline `try_files` arguments.
- Rationale: covers normal try_files/php_fastcgi and SPA-fallback flows with Caddy v2.11.9 semantics; custom filesystems are a separate fail-closed feature.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/matchers.rs` file-matcher tests (globs/classes/escapes/containment/trailing slash/split/fallback/`=NNN`), oracle try_files and Caddy v2.11.9 file-matcher comparisons, `crates/config/tests/matchers_adapt.rs::file_matcher_block_forms_and_errors`, upstream `php_fastcgi_expanded_form`, local `file_matcher`.

## DIV-0078 — Per-server access-log association is implemented
- Status: fixed
- Area: Observability
- Caddy behaviour: `apps.http.servers.*.logs` selects logger names/skip hosts/default logger.
- caddy-rs behaviour: typed `ServerLogConfig` (default_logger_name, logger_names, skip_hosts, skip_unmapped_hosts, should_log_credentials, trace) is honored by runtime access-log emission with Caddy's mapping-over-skip order and wildcard host matching; global `logging.logs[]` sinks still gate output. Residual: `should_log_credentials`/`trace` are modeled but not applied, and multi-wildcard host semantics differ slightly; named-logger include/exclude filters are evaluated against each entry's logger name (`T-ADMIN-047`).
- Rationale: core association behavior implemented; filter refinement is tracked.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_per_server_logs.rs`.

## DIV-0079 — Automatic-HTTPS derivation residuals are bind-address and on-demand granularity
- Status: mitigated
- Area: TLS
- Caddy behaviour: derives sites/listeners from site addresses; supports mixed listener sets, multiple non-standard HTTPS ports, explicit `http://` hosts, multiple servers per host, IP/empty hosts and manual certificates; TLS is per listener (`port != http_port`), redirect Locations follow `makeRedirRoute`, redirect servers preserve bind addresses, and on-demand TLS/ARI/background issuance apply.
- caddy-rs behaviour: the derivation plan covers mixed cleartext/TLS listener sets, multiple non-standard HTTPS ports (Caddy winner rule), per-host winning redirect ports across servers, explicit-http skip hosts, manual-certificate redirects with `ignore_loaded_certificates`, hostless catch-all redirects, IP internal certificates, and `AutomaticHttpsPlan::redirect_location` implements Caddy's Location suppression. The server applies that Location rule and the `port != http_port` TLS decision. Remaining differences: the derived redirect/challenge listener is one wildcard `:http_port` instead of Caddy's per-bind-address redirect servers, `disable_redirects` still derives a challenge listener, issuance/OCSP is synchronous (no background retry), and on-demand TLS is unsupported. ARI renewal timing is implemented in the scheduler (DIV-0012) and reloads reuse the active generation's in-memory certificates (DIV-0064).
- Rationale: derivation and the observable redirect/TLS decisions are verified; the remaining bind-address granularity and on-demand features are tracked separately.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/automatic_https.rs` (`plan_derives_mixed_cleartext_and_tls_listeners`, `plan_derives_multiple_non_standard_https_ports`, `plan_keeps_explicit_http_hosts_cleartext_when_mixed_with_implicit_https`, `plan_multiple_servers_for_same_host_use_caddy_winning_redirect_port`, `plan_manual_tls_server_still_gets_redirects`, `plan_derives_catch_all_redirects_for_hostless_tls_servers`, `plan_redirect_location_follows_caddy_make_redir_route`), `crates/server/tests/http_auto_https.rs`.

## DIV-0080 — request_body handler unknown JSON fields are rejected
- Status: accepted
- Area: HTTP
- Caddy behaviour: JSON decoding ignores unknown fields in handler configs.
- caddy-rs behaviour: `request_body` handler (and several other handlers) reject unknown fields with located errors, deliberately following the fail-closed compatibility rule; Caddyfile `request_body` adaptation (max_size/set/matcher) matches Caddy exactly.
- Rationale: silent config typos are worse than loud rejection; DIV-0016 convention.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/handlers.rs` request_body tests.

## DIV-0081 — map handler matches Caddy's JSON semantics; lazy evaluation remains
- Status: mitigated
- Area: HTTP
- Caddy behaviour: `map` evaluates lazily when a destination is first used, supports Go regular expressions (look-around, word boundaries, backreferences, named-group `$name` expansion) and Go scalar formatting.
- caddy-rs behaviour: `http.handlers.map` evaluates when the handler runs and implements ordered exact/regexp mappings, numeric `$1`/`${1}` captures, positional defaults, null-output fall-through, multiple destinations, scalar output coercion and placeholder expansion; destinations are visible via `{http.vars.*}`. The shared linear-time `regex` engine supports Go RE2 constructs, including named `$name` captures, word boundaries, lazy quantifiers and inline flags; look-around/backreferences fail loudly, and the Unicode class residual is documented in DIV-0015. Eager evaluation is observationally equivalent unless a later handler mutates the source before a destination is used. Extreme float formatting can differ.
- Rationale: covers adapted Caddyfile maps; unsupported regex features fail closed.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/handlers.rs` map tests, `crates/http/tests/map.rs` router tests (order, regex, null fallback, defaults, multiple destinations, scalar coercion), `.scratch/logs/w19-templates-map/map-comparison.txt` (4/4 oracle MATCH).

## DIV-0082 — FastCGI transport covers the core protocol; TLS-derived CGI vars and the escaped-path check remain narrower
- Status: open
- Area: Proxy / FastCGI
- Caddy behaviour: FastCGI transport (`fastcgi.go`) with a CGI environment derived from the decoded/cleaned request path (`NormalizedPath`), NUL-byte rejection, SCRIPT_FILENAME/SCRIPT_NAME/PATH_INFO/DOCUMENT_ROOT/PATH_TRANSLATED rules, header→HTTP_* mapping (Host/Proxy skipped), operator `env` applied last, absolute per-connection read/write deadlines, Content-Length-bounded response bodies with surplus discarded, chunked decoding with chunked precedence, `Location`-without-`Status` → 302, body suppression for HEAD/1xx/204/304, strict MIME header parsing, 502 on malformed app/protocol status, and `capture_stderr` at WARN (ERROR for 4xx/5xx). For TLS requests it also sets `HTTPS=on`, `SSL_PROTOCOL` from `tlsProtocolStrings` (`TLSv1`/`TLSv1.1`/`TLSv1.2`/`TLSv1.3`) and `SSL_CIPHER` from the Go/IANA name of the negotiated suite. Active checks over a FastCGI transport are plain HTTP probes (not FastCGI-aware), and the client opens one connection per request (`keepAlive` is a TODO; no pooling/multiplexing).
- caddy-rs behaviour: implements the FastCGI record protocol over TCP/Unix (BEGIN/PARAMS/STDIN/STDOUT/STDERR/END, 65500-byte record buffering with Caddy's parameter truncation, request id 1, no multiplexing), the CGI environment with decoded/cleaned path and NUL rejection (400 before dialing), SERVER_PROTOCOL from the negotiated request version, Unix REMOTE_ADDR="@", SERVER_ADDR from the listener local address, operator env applied after HTTP_*, HTTPoxy mitigation, absolute connection read/write deadlines, Content-Length-bounded and bodyAllowed-suppressed response bodies, chunked decoding with first-token detection, Location→302, strict MIME header parsing (a bare HTTP status line is a 502), malformed record version/request-id rejection, app/protocol-status 502 mapping, `resolve_root_symlink`, `capture_stderr` at WARN/ERROR by status, and retries with buffered bodies (`CONTENT_LENGTH` required; 411 when unknown). HTTPS/SSL_PROTOCOL/SSL_CIPHER come from the negotiated TLS session threaded through the request (`TlsVersion`/`TlsConnection`: `TLSv1`/`TLSv1.1`/`TLSv1.2`/`TLSv1.3` and Go/IANA cipher names; unknown cipher ids omit `SSL_CIPHER` like Caddy's lookup loop). HTTP/3 requests expose TLS 1.3 but no cipher because quinn does not expose the negotiated suite. Gaps: Caddy's escaped-vs-decoded RawPath script consistency check is not reproduced; active health checks over FastCGI are rejected loudly instead of Caddy's plain HTTP probes; no live php-fpm/oracle acceptance yet.
- Rationale: protocol and CGI parity cover php-fpm-style deployments; the remaining environment/security details are explicit, tested gaps rather than silent approximations.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/fastcgi.rs` (33 tests: protocol, environment, TLS-derived CGI variables, decoded paths, NUL rejection, env precedence, Content-Length/chunked/body suppression, Location→302, strict headers, absolute deadlines, malformed records, symlink root, Unix socket), `crates/config/tests/fastcgi.rs`.

## DIV-0083 — File log rotation and console encoder
- Status: mitigated
- Area: Admin access-log file writer / encoder
- Caddy behaviour: FileWriter (`external/caddy/modules/logging/filewriter.go`) rotates by size (`roll_size_mb`), interval (`roll_interval`), clock minutes (`roll_minutes`) or daily times (`roll_at`), keeps `roll_keep` files / `roll_keep_days` days, optionally compresses rolls (default gzip), can use local timestamps (`roll_local_time`) and a custom Go `backup_time_format`; the console encoder (`modules/logging/encoders.go`) honours `time_format`, `level_format` (`lower`/`upper`/`color`), `message_key`/`level_key`/`time_key`/`name_key` and `line_ending`.
- caddy-rs behaviour: size, interval, minute/clock rotation, `roll_keep`/`roll_keep_days`, numeric `mode`/`dir_mode`, console `time_format`, `level_format`, the four encoder key options and `line_ending` are implemented. `roll_compression` accepts `none`, `gzip` and `zstd`: rotated files are renamed to `<filename>.<unix-millis>` and then stored as `.gz`/`.zst` archives (the uncompressed copy is removed only after the archive is flushed, and retention keeps pruning compressed names); `none` stays the default rather than Caddy's gzip. `roll_local_time: true`, a custom `backup_time_format`, `dir_mode: inherit`/`from_file` and console `time_local: true` are rejected with located errors because this build has no timezone database or Go time-layout renderer.
- Rationale: avoids silent disk-usage/format divergence while shipping the compression that matters operationally; the remaining options are advertised loudly and tracked here.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/sink.rs` (`size_rotation_rolls_and_prunes_backups`, `interval_rotation_rolls`, `gzip_and_zstd_rotation_produce_readable_archives`, `console_encoder_honors_time_and_level_format_options`, `console_encoder_honors_level_key_and_timestamp_options`, `unsupported_rotation_options_are_located_errors`) and `crates/admin/src/logging_config.rs` mapping tests.

## DIV-0084 — Graceful shutdown differs on no-grace default, reload grace and Caddyfile options
- Status: open
- Area: Runtime
- Caddy behaviour: eternal grace when unset, reload-time graceful closes with delay, Caddyfile global grace_period/shutdown_delay.
- caddy-rs behaviour: explicit grace/delay semantics implemented for signals and `/stop` (including tunnels, second-signal force, admin drain); absent grace keeps historical immediate force-close; reload-time listener removal closes gracefully without delay/grace; Caddyfile global options are not adapted.
- Rationale: explicit configuration works; default/reload/Caddyfile behavior are follow-ups.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_graceful_shutdown.rs`, CLI signal tests.

## DIV-0085 — Client-auth CA pools provision the implicit `local` PKI authority on demand
- Status: fixed
- Area: TLS
- Caddy behaviour: `client_authentication.ca` accepts `pki_root`/`pki_intermediate` sources with `authority` ids. The PKI app provisions a default `local` authority on demand (`GetCA`), even when `certificate_authorities` is empty, so a pool may reference `local` without declaring `apps.pki`. `caddy validate` provisions the app, generating the default CA material in storage as a side effect.
- caddy-rs behaviour: when `apps.pki` does not declare `local`, the loader provisions Caddy's default authority at `<data-dir>/pki/authorities/local` on first use and reuses it afterwards (existing material is loaded, never regenerated). `validate` resolves the same drop-in data path `run` uses (`CADDY_RS_DATA_DIR` / XDG / HOME), so validating with no explicit storage accepts a pool referencing `local` and creates the material where the `pki_root`/`pki_intermediate` loaders read it. Material reused from a real Caddy data directory is accepted even though Caddy stores SEC1 `EC PRIVATE KEY`. A missing or unwritable storage root still fails loudly, naming the authority and the file.
- Rationale: Caddy's side effect during `validate` is part of its contract for this configuration; reproducing it is what makes the fixture pass without a known divergence.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_client_auth.rs` (`implicit_local_ca_authority_is_provisioned_for_client_auth_pools`, `validate_without_a_storage_root_provisions_the_implicit_local_ca`, `unwritable_storage_root_fails_loudly_for_the_implicit_local_ca`), `crates/tls/src/client_auth.rs` (`provisions_the_implicit_local_authority_once_and_reuses_it`, `implicit_local_without_a_data_root_stays_a_located_error`, `explicitly_configured_local_authority_is_never_generated`, `reuses_certificates_from_a_real_caddy_data_directory_without_its_keys`); oracle fixture `tls_client_auth_combined_trust_pool_pki` now passes with no known divergence.

## DIV-0086 — Upstream TLS client certificates support static files and an inline extension
- Status: open
- Area: Proxy
- Caddy behaviour: upstream client certificates may be automated; CA pools include pki/storage/http providers; curves are configurable; certificate reload/OCSP config exists; Caddy's strict module decoding rejects an unknown inline `client_certificate` field.
- caddy-rs behaviour: static `client_certificate_file`/key mTLS (validated at configuration load: missing file, bad PEM, encrypted key and cert/key mismatch are located errors) and the inline `client_certificate` PEM extension (mutually exclusive with the file fields; Caddy rejects the field as unknown) work with real handshakes; `client_certificate_automate`, `curves`, pki/storage/http CA providers and cert reload/OCSP config are rejected loudly; `except_ports` matches the dial port.
- Rationale: static mTLS covers common upstreams and inline PEM serves generated configurations; automation is a lifecycle feature.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/handler.rs` mTLS inline/file/wrong/missing tests, `crates/proxy/src/tls.rs` client-certificate load-error tests; oracle rejection of the inline field recorded in `.scratch/logs/w17-proxy-tls-inline.json`.

## DIV-0087 — file matcher glob/error support matches Caddy v2.11.9 except custom filesystems and non-UTF-8 names
- Status: open
- Area: HTTP
- Caddy behaviour: file matcher supports Go `filepath.Glob` patterns, `=NNN` error responses and custom filesystems; malformed patterns are logged and skipped; `first_exist_fallback`'s last entry is a literal unconditional fallback.
- caddy-rs behaviour: `try_files` globbing supports `*`/`?`/`[...]` classes/escapes with placeholder-value escaping, sorted deterministic results, expanded-pattern trailing-slash restoration, directory fall-through, traversal containment, and `=NNN` short-circuit status responses (with Caddy's raw-digits error message) in `first_exist`/`first_exist_fallback`; the last fallback entry matches literally even when absent, matching Caddy v2.11.9 (`makeLiteralCandidate`). Verified against a real Caddy v2.11.9 oracle for split remainders, missing fallbacks, error-route status/message, directory fall-through, `*`/class/`?`/trailing-slash globs and `..` containment. Remaining differences: malformed glob patterns are treated as non-matching rather than logged `ErrBadPattern`, non-UTF-8 filenames are compared lossily, the path separator is always `/` (Unix build), and custom `fs` modules are rejected loudly.
- Rationale: covers try_files/php_fastcgi/SPA flows; remaining forms either fail closed or differ only in logging/encoding.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/matchers.rs` glob/error/trailing-slash/fallback/error-route tests, Caddy v2.11.9 oracle comparisons.

## DIV-0088 — PROXY protocol listener wrapper: TLVs and AF_UNIX names are a caddy-rs extension; the wrapper remains a strict subset
- Status: open
- Area: HTTP listener
- Caddy behaviour: `listener_wrappers` proxy_protocol (v1/v2, policies, allow/deny CIDRs, timeout) with real client addresses; Caddy v2.11.9 wraps the listener with `pires/go-proxyproto` v0.15.0, which parses the v2 address block (INET/INET6/AF_UNIX names, an empty `net.UnixAddr` name renders as `@`), copies the raw TLV vector but exposes no TLV data (`Header.TLVs()` is never called), does not validate CRC32C, and caps the v2 payload at 4096 bytes; the Caddyfile `servers` block is supported.
- caddy-rs behaviour: JSON `apps.http.servers.*.listener_wrappers` supports proxy_protocol v1/v2 (LOCAL/PROXY/UNKNOWN, INET/INET6/UNIX families, timeout/allow/deny/fallback policies) and the `tls`/`http_redirect` ordering markers; parsing happens before TLS and updates remote/local request variables. v2 TLVs (ALPN, AUTHORITY, CRC32C, UNIQUE_ID, SSL with client/verify and version/CN/cipher/sig_alg/key_alg/group/sig_scheme/client_cert sub-TLVs, NETNS; unknown/NOOP retained) are decoded with loud framing/UTF-8/length validation and a 4096-byte payload cap. Caddy exposes no TLV surface, so caddy-rs exposes them as a clearly-marked extension: `{http.vars.proxy_protocol.tlv.*}` (`alpn`, `authority`, `unique_id`, `netns`, `crc32c`, `crc32c_valid`, `ssl.*`) and `{http.vars.proxy_protocol.unix.remote|local}`. CRC32C is computed over the header with the checksum field zeroed and surfaced with a validity flag but not enforced (Caddy never validates it). v2 `AF_UNIX` headers are accepted; names (empty → `@`) are parsed like `parseUnixName` and `{http.request.remote*}` uses the Unix name with an empty port, matching Caddy. The Caddyfile `servers [<addr>] { listener_wrappers { ... } }` adaptation matches Caddy for this narrow subset (integer-ns timeout, allow/deny, upper-case fallback policy with `ignore` omitted, `tls`/`http_redirect`, per-address application, duplicate-address rejection). Gaps: AF_UNIX access-log remote values remain the transport/empty value (the textual override applies to request placeholders, not the pre-request log snapshot), LOCAL-command TLVs are not decoded, unknown TLVs are retained but not surfaced, TLV vars do not apply over HTTP/3 (no wrapper), `{http.request.local.*}` is exposed only through request vars, SKIP leaves header bytes unread, all other `servers` sub-options/wrapper arguments stay located errors, and there is no live-Caddy TLV oracle (Caddy has no TLV surface).
- Rationale: covers load-balancer deployments and makes upstream-provided TLVs usable without pretending Caddy has the same surface; the extension is prefixed and documented, and the remaining wrapper gaps stay fail-closed.
- Tracking: T-COMPAT-003
- Test: `crates/server/src/proxy_protocol.rs` (6 unit tests: v1/v2, typed TLVs/SSL/CRC32C, malformed/oversized, AF_UNIX names), `crates/server/tests/proxy_protocol.rs` (10 integration tests incl. TLV request vars, AF_UNIX `{http.request.remote*}`/vars, policies/allow-deny/fallback, TLS-before-handshake), `crates/http/src/placeholders.rs` remote-override test, core validation tests, local `servers_*` oracle fixtures.

## DIV-0089 — Admin upstream counters are cumulative, not in-flight/expiring
- Status: open
- Area: Admin / Proxy
- Caddy behaviour: `/reverse_proxy/upstreams` reports `num_requests` as active/in-flight requests and `fails` as recent failures with expiry, merged with dynamic upstreams.
- caddy-rs behaviour: live counters are wired end-to-end (proxy pool -> server `ProxyUpstreamStatusSource` -> `AdminApi::with_upstream_status_source`) but are cumulative attempts (retries counted) and cumulative failures since generation configuration, reset on reload; duplicate addresses are summed and only configured static upstreams are listed. Endpoint shape/status match Caddy. Not exercised by the runtime oracle because the counter semantics differ by design (no allowlist entry exists for this probe).
- Rationale: cumulative counters are simpler and useful operationally; Caddy-exact in-flight/expiry semantics are a follow-up.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_upstream_status.rs`; `crates/admin/src/lib.rs::reverse_proxy_upstreams_merges_runtime_counters_when_a_source_is_registered`.

## DIV-0090 — Admin CORS is implemented with narrow host-check accommodations
- Status: fixed
- Area: Admin
- Caddy behaviour: admin CORS echo/preflight/origin handling, DNS-rebinding Host rejection and ServeMux redirect quirks.
- caddy-rs behaviour: CORS echo (`Access-Control-Allow-Origin`, scheme lowercase/host casing preserved, path stripped, no Vary), OPTIONS preflight capability headers and per-endpoint semantics, origin allow-list with Referer fallback, `Origin: null`/WebSocket mitigations and Caddy's error messages; Host check rejects mismatches with `host not allowed:`. Accommodations: Host check runs for cross-site contexts (Origin/Sec-Fetch present or origin enforcement on) to keep CLI/harness clients working, port-less Host is accepted, and only the `/pki` → `/pki/` redirect quirk is emulated.
- Rationale: browser-driven admin clients are safe and Caddy-compatible; accommodations keep local tooling functional.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/origin.rs` tests, real-Caddy oracle probes.

## DIV-0091 — Rewrite fields match Caddy; relative URI targets remain unsupported
- Status: mitigated
- Area: HTTP
- Caddy behaviour: `http.handlers.rewrite` supports `uri` (component-wise path/query/fragment setting, placeholders, query escaping and append-only duplicate keys, bare `?` clears the query, relative targets such as `foo.html` accepted), `method`, escape-aware/case-insensitive `strip_path_prefix` and `strip_path_suffix` with path cleaning/canonicalization, `uri_substring` (Caddy `CleanPath` with the `//` merge rule, path+query replacement, limit), `path_regexp` on the escaped path with captures whose `{http.regexp.*}` values are percent-encoded (slashes preserved) when used in the `uri` path part (upstream 7591cff1fb03, post-pin), and ordered `query` operations (rename/set/add/replace/delete); a changed `uri_substring`/`path_regexp` result is then canonicalized like prefix/suffix stripping (anchor a relative result, resolve dot segments, preserve repeated slashes; upstream fc6c202ea60d, post-pin), and a changed direct `uri` path is canonicalized the same way while an unchanged path and an explicit `OPTIONS *` target are left alone (upstream f4c634f0ed3d, post-pin).
- caddy-rs behaviour: all of those fields are implemented in the HTTP engine with Caddy's ordering, escape-aware prefix/suffix trimming, `//`-controlled path cleaning, component-wise URI setter with query escaping/duplicate preservation, path-placeholder escaping/canonicalization, file-matcher path placeholder escaping, fragment dropping, and query operation ordering/encoding; empty values are no-ops. The Caddyfile adapter already emits Caddy's canonical JSON for every rewrite/`uri` form (oracle-adapted outputs byte-identical), so the old adapter-gap half is closed. A `uri_substring` or `path_regexp` replacement that changes the path is canonicalized before it is installed, so removing the component in front of `..` (`/mount../secret` -> `/secret`) or a replacement that introduces dot segments cannot leave a path a downstream `path` matcher sees differently from `file_server` (path-guard bypass, upstream fc6c202ea60d). A direct `uri` rewrite whose path changes is canonicalized the same way before the request target is rebuilt, so a placeholder such as `/public/../secret` becomes `/secret` while `/a//b/` keeps its repeated slashes and an unchanged `{http.request.uri.path}` stays byte-identical (upstream f4c634f0ed3d); the URI setter now leaves `.` unescaped like Go's `EscapedPath` (it used to emit `%2E`), which is what lets the cleaner see dot segments, and the changed-vs-unchanged decision compares decoded bytes rather than a lossy UTF-8 String, so paths that differ only in invalid percent escapes are still canonicalized. A non-absolute target is rejected loudly (an authority-only target such as `secret` is no longer silently accepted as a pathless URI), except on `OPTIONS`, where a `*` target — including one produced by a placeholder — is kept as the asterisk-form `*`; upstream renders a placeholder `*` as `/%2A`, which is an escaped-model residual. Regexp captures (`{http.regexp.*}`, from any matcher) inserted into the `uri` path part are percent-encoded with slashes preserved before expansion, mirroring post-v2.11.9 upstream 7591cff1fb03 (the v2.11.9 pin inserts them raw; port task T-PORT-7591cff1fb03, security motivated: a raw capture re-decodes into a path separator or query delimiter after route guards have run), so a capture such as `%2e%2e%2f` from a double-encoded request path cannot re-decode into a real `../` after route guards have run, and a capture that decodes to `?` stays path data instead of starting a query string; names ending in `_escaped` are inserted unchanged and the configured query part keeps the query builder's own escaping. Residual gaps: the canonicalization operates on the escaped URI path without decoding it first, so encoded dots and separators are not resolved before cleaning and can still slip past a downstream `path` guard: reviewer probes show `rewrite` + `/mount%2e/secret` and `/mount%2fsecret` serve the file (200) behind a `path /secret*` 403 guard, while `/mount%2e%2e/secret` is blocked (403) by `file_server`'s traversal rejection. Upstream decodes the path first and does not have this residual, so it stays a documented divergence against upstream, tracked by T-PORT-fc6c202ea60d; relative `uri` targets (`foo.html`) are rejected with a located error because `http::Uri` cannot represent relative request targets (Caddy accepts them); `path_regexp` uses the same linear-time `regex` engine as the matcher (named/numeric captures, `$name`/`$1` replacement, look-around/backreferences loud, Unicode class residual — DIV-0015); Go `url.ParseQuery` semicolon/invalid-escape leniency is not replicated.
- Rationale: the runtime follows Caddy's component-cleaning and query-building rules rather than naive string slicing; the relative-URI rejection is fail-closed instead of silently changing the target to an absolute path.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/handlers.rs` rewrite unit tests (incl. `rewrite_uri_substring_canonicalizes_the_replaced_path`, `rewrite_uri_substring_canonicalizes_a_replacement_that_introduces_dot_segments`, `rewrite_path_regexp_canonicalizes_the_replaced_path`, `rewrite_uri_canonicalizes_a_changed_path`, `rewrite_uri_canonicalizes_a_literal_path_with_dot_segments`, `rewrite_uri_preserves_repeated_slashes_and_leaves_an_unchanged_path_alone`, `rewrite_uri_leaves_an_explicit_options_asterisk_target_alone`, `rewrite_uri_keeps_rejecting_relative_targets`, `rewrite_uri_detects_a_change_that_differs_only_in_invalid_utf8`), `crates/http/tests/rewrite.rs` (17 router tests, incl. `regexp_capture_double_encoded_traversal_stays_data`, `regexp_capture_decoded_question_mark_stays_in_path`, `regexp_capture_slashes_are_preserved`, `regexp_capture_configured_query_is_unaffected`, `regexp_capture_unnamed_and_named_forms_agree`), `.scratch/logs/w22-rewrite/comparison-final.txt` (8/8), `comparison4.txt` (fragment/escaped prefix/injected query/raw query match; relative target documented DIFF), `caddy-adapted.json`/`caddyrs-adapted.json` equal.

## DIV-0092 — Caddyfile grace options are stricter than Caddy's adapter for duplicates and extra args
- Status: mitigated
- Area: Caddyfile / Runtime
- Caddy behaviour: global `grace_period`/`shutdown_delay` accept negative durations, keep the last duplicate value, and silently ignore extra arguments. The runtime tests both with `> 0`, so zero and negative mean "no limit" — an eternal grace period and no shutdown delay (`modules/caddyhttp/app.go` 731, 757).
- caddy-rs behaviour: negative durations are accepted end to end — the adapter emits Caddy's exact negative nanosecond JSON (`grace_period -1s` → `-1000000000`), the typed model stores a signed `CaddySignedDuration`, and the runtime treats any value `<= 0` as no limit, matching Caddy's `> 0` tests (covered by `shutdown_timing_tests::negative_grace_period_and_shutdown_delay_mean_no_limit`). A bare integer such as `-500` is rejected with Caddy's own message (`missing unit in duration`). Remaining loud divergences: duplicate lines are rejected instead of keeping the last value, and extra arguments are rejected instead of ignored.
- Rationale: a negative duration is a real Caddy construct with clear semantics, so it must work; a duplicated or over-specified option is ambiguous, and failing closed keeps the configuration honest.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/upstream_adapt.rs` (`negative_shutdown_durations_adapt_like_caddy`), `crates/config/src/parser.rs` (`invalid_grace_period_values_fail_loudly` now asserts negative values parse), `crates/server/src/runtime.rs` (`shutdown_timing_tests`), `crates/core/src/config.rs` (signed decode).

## DIV-0093 — Default reverse_proxy selection is round_robin, Caddy defaults to random
- Status: fixed
- Area: Proxy
- Caddy behaviour: without an explicit `lb_policy`, Caddy selects upstreams with the `random` policy.
- caddy-rs behaviour: the default selection is now Caddy's `random` policy — health-aware reservoir sampling over an atomically seeded SplitMix64 — and explicit policies (including round_robin) behave exactly as before.
- Rationale: the default now matches Caddy; no explicit policy was changed.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/balancer.rs::random_policy_is_deterministic_with_seed_and_respects_health` plus the selection-policy tests.

## DIV-0094 — Access-log remote vs resolved client address
- Status: fixed
- Area: Server observability
- Caddy behaviour: `request.remote_ip`/`request.remote_port` are the transport peer (`strings.SplitHostPort` of `RemoteAddr`; Unix peers log `remote_ip:"@"` with an empty port); `request.client_ip` is the trusted-proxy-resolved value derived by `determineTrustedProxy` (peer unless the peer is trusted, then the configured `client_ip_headers` bare IP; untrusted Unix peers resolve to `""`) — `modules/caddyhttp/server.go:1377-1380,1419-1468`, `marshalers.go:33-60`.
- caddy-rs behaviour: the same split is implemented. `remote_ip`/`remote_port` stay the transport peer (Unix `"@"`/empty), and `client_ip` is resolved from the server-level `trusted_proxies`/`client_ip_headers` policy with Caddy's bare-IP, no-port semantics, strict right-to-left scanning and the untrusted-Unix `""` fallback. Resolution runs only when an access-log sink is enabled and covers HTTP/1.1, HTTP/2, h2c and HTTP/3 (HTTP/3 now also emits access entries when logging is configured).
- Rationale: trusted-proxy deployments must log the real client, not the proxy's peer address.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_client_ip_logs.rs` (trusted/untrusted TCP, custom `client_ip_headers`, trusted/untrusted Unix `"@"` cases).

## DIV-0095 — cookie and random_choose load-balancing policies are unsupported
- Status: fixed
- Area: Proxy
- Caddy behaviour: `cookie` (sets/reads a session cookie through the retry loop) and `random_choose N` selection policies.
- caddy-rs behaviour: both are implemented with Caddy-compatible semantics: `cookie` routes by Caddy's `HMAC-SHA256(secret, dial)` sticky cookie (Go-compatible Cookie parsing/serialization, `Set-Cookie` echo on fallback selection, optional `max_age`, invalid/unknown values fall through to the fallback policy), and `random_choose N` samples a random sub-pool of N healthy upstreams with reservoir sampling (N must be >= 2). random/weighted_round_robin/ip_hash/client_ip_hash/uri_hash/header/query/first/round_robin/least_conn remain implemented; unknown policy names still fail loudly by name.
- Rationale: the full Caddy policy set is implemented; fail-closed is retained only for unknown names.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/balancer.rs` (`cookie_policy_sets_sticky_cookie_and_pins_to_it`, `cookie_policy_max_age_emits_max_age_attribute`, `random_choose_subpool_respects_health_and_choose`).

## DIV-0096 — Network/TLS matcher Caddyfile forms and core registry entries are incomplete
- Status: fixed
- Area: HTTP / Caddyfile / Core
- Caddy behaviour: `remote_ip`, `client_ip`, `protocol`, `tls` (and Caddy's TLS-connection-policy `local_ip`) matchers in Caddyfile and JSON, registered in the module registry.
- caddy-rs behaviour: runtime matchers are implemented (`path_regexp` with capture placeholders, `remote_ip`/`client_ip` with CIDR/private_ranges, `protocol` schemes/versions, `tls` handshake_complete, `local_ip` extension) with loud rejection of unsupported TLS metadata. The core builtin registry now registers `http.matchers.remote_ip`, `client_ip`, `protocol` and `tls` (plus the caddy-rs extension `local_ip`), and the Caddyfile adapter emits the `protocol`/`tls` matcher forms, so adapted JSON validates against the default registry without overlays.
- Rationale: registry and adapter completion landed with T-ROUTE-038; `local_ip` remains a documented caddy-rs extension because Caddy v2.11.7 has no HTTP `local_ip` matcher.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/matchers.rs`, `crates/config/tests/matchers_adapt.rs`, `crates/http/tests/matchers_fixtures.rs` (builtin-registry validation), oracle runtime probes.

## DIV-0097 — ACME challenge order was deterministic and alternate ports are unsupported
- Status: mitigated
- Area: TLS / ACME
- Caddy behaviour: acmez selects challenges with adaptive randomized ordering, retrying the order with the next solver-backed challenge type when validation fails with a recoverable problem (`connection`, `dns`, `serverInternal`, `unauthorized`, `tls`; up to three attempts, one second apart), and supports alternate challenge ports.
- caddy-rs behaviour: challenge order now matches acmez's adaptive randomized selection (one-time shuffled pool, stable descending success-ratio ordering, per-issuer `AdaptiveChallengeSelector` in `crates/tls/src/acme/adaptive_challenge.rs`) and the issuer runs acmez's `ObtainCertificate` retry loop (`crates/tls/src/issuer.rs`): the failed challenge type is remembered per identifier and the next attempt creates a fresh order and picks the next solver-backed offered type, for the same five problem classes, up to three attempts with acmez's one-second inter-attempt pause. `alternate_port` remains unsupported and fails loudly with a located config path; `challenges` config is validated with loud unknown keys/options; CA problem details and sub-problems, and verbatim `Retry-After`, now match Caddy/acmez.
- Rationale: ordering and retry parity are implemented for issued orders; alternate ports require HTTP/TLS listener wiring outside the ACME crate and stay fail-closed (tracked by T-TLS-064).
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/acme/adaptive_challenge.rs` selector tests; `crates/tls/src/issuer.rs` retry-fallback and `AcmeIssuerConfig` alternate-port rejection tests; `crates/server/tests/http_auto_https.rs` end-to-end adaptive selection and fallback issuance.

## DIV-0098 — Error routes (`errors` / `handle_errors`) bridge handler error statuses
- Status: accepted
- Area: HTTP / Caddyfile / Core
- Caddy behaviour: `apps.http.servers.*.errors.routes` (Caddyfile `handle_errors [<codes>] {...}`) runs the error chain only when a handler returns a `HandlerError`; handlers that write an error status as a normal response (e.g. `static_response` with `403`, or an `error` handler's own HTTPError) do not enter the chain. The error chain exposes `{http.error.status_code}`, `{http.error.status_text}`, `{http.error.message}`, `{http.error.trace}` and `{http.error.id}`; an unhandled error is written as the status header with an empty body. `errors` routes are site-block only; `error` routes are assembled/sorted with host-wrapping rules per issue #5124.
- caddy-rs behaviour: `apps.http.servers.*.errors.routes` is implemented and the Caddyfile `handle_errors [<codes>] {...}` adaptation emits Caddy's canonical error-route JSON (code filters as an `expression` status subset; host wrapping per Caddy). The four error placeholders are exposed: `status_code`/`status_text`/`message` implemented, `trace`/`id` present but empty (no handler-trace metadata or error IDs in caddy-rs). Differences: (1) the error chain also runs for handler RESPONSES with status >= 400 when `errors` is configured — caddy-rs `reverse_proxy` returns 502/503/504 as normal responses, so bridging them lets upstream and `error`-handler statuses reach `handle_errors` (required for the acceptance scenarios); (2) an unhandled `HandlerError` fallback body is `<status> <reason>` text rather than an empty body; (3) `error` handler statuses may be placeholders/strings in Caddy where only the implemented subset is parsed (unsupported parsing fails loudly); (4) unknown `errors` fields are rejected instead of ignored (hardening); (5) ordering is pinned to request construction: every error-chain entry point re-enters with a clone of the routed request, header map included (`crates/http/src/router.rs` `evaluate_routes` → `run_error_routes`), so request-level sanitisation must run before the first route — the header-alias filter (`T-HTTP-155`) therefore hooks at construction (R8, `T-HTTP-165`) rather than in a handler, because a handler-side filter would leave error-route proxy/FastCGI handlers seeing the pre-sanitisation metadata. Until that filter lands, no header is dropped on trunk and aliases reach primary and error-route handlers alike (baseline gap tracked by `T-HTTP-155`, not an extra divergence).
- Rationale: error routes are required for the Jellyfin/reference deployment error pages; bridge-by-status is a deliberate, documented departure so upstream failures can render the configured error page, and the placeholder/metadata gaps are honest limitations rather than silent approximations.
- Tracking: T-COMPAT-003
- Test: `crates/http/tests/error_routes.rs` (`error_routes_run_for_error_status_responses`, status filters, fallback, `error_routes_see_the_same_request_headers_as_the_primary_chain` — error routes inherit the routed request's header map, so sanitisation must run at construction), `crates/server/tests/http_error_routes.rs` (real listener `error` handler -> error route; adapted Caddyfile end to end; upstream error status triggers `handle_errors`), `crates/config/tests/error_routes_adapt.rs` (oracle-exact adaptation).

## DIV-0099 — `reverse_proxy` `handle_response` matcher and copying limits
- Status: accepted
- Area: Proxy / HTTP / Caddyfile
- Caddy behaviour: `reverse_proxy.handle_response[]` runs response routes (matchers over status/headers/vars, `copy_response`, `copy_response_headers`, `replace_status`, arbitrary inner handlers); `copy_response` streams the upstream body, and `copy_response`/`copy_response_headers` outside `handle_response` parse but fail per request.
- caddy-rs behaviour: `handle_response` is implemented (response status exact lists/classes, response-header wildcards, non-matching pass-through, `status_code`/`replace_status`, synthetic responses, `copy_response` with optional status, `copy_response_headers` include/exclude) and the Caddyfile `handle_response [@name] {...}`, `replace_status [@name] <status>`, `copy_response [<status>]` and `copy_response_headers {include|exclude ...}` forms adapt exactly. Differences: (1) `copy_response` buffers the upstream body (Caddy streams it); buffering happens only when `copy_response` is configured; (2) response-route matchers are limited to no matcher or the canonical `not vars` header-presence check, arbitrary request matchers inside `handle_response` routes fail loudly (`NotImplemented`, T-PROXY-037); (3) `copy_response`/`copy_response_headers` outside `handle_response` are rejected loudly at validation/apply instead of failing per request (stricter/safer); (4) inner handler sets other than headers/vars/static_response/copy_response/copy_response_headers, non-string `vars` values, and unsupported status parsing are located errors.
- Rationale: covers the forward_auth and error-response use cases the reference deployment needs, without silently approximating streaming or arbitrary matcher behaviour. Ordering matches Caddy's two-phase collection (`T-CONF-058`): every `replace_status` entry is appended during unmarshal and every `handle_response` block during finalize, so interleaved declarations emit all `replace_status` entries first, then all `handle_response` entries, then a stable matcher-less-last partition.
- Tracking: T-COMPAT-003
- Test: `crates/proxy` `handle_response` tests (status lists/classes, header wildcards, pass-through, status override, copy body/headers, loud rejection), `crates/config/tests/handle_response_adapt.rs` (oracle-exact adaptation), `crates/server/tests/http_error_routes.rs` (upstream 503 -> response route), `crates/http/tests/error_routes.rs`. `crates/server/tests/http_forward_auth_handle_response.rs` (`user_handle_response_runs_for_a_non_2xx_auth_response`, `canonical_header_copy_runs_before_the_user_handler_for_a_2xx_auth_response`, `log_skip_inside_the_user_handle_response_is_rejected_loudly_by_the_runtime`) — `T-CONF-057`. `crates/config/tests/replace_status_order_adapt.rs` (`matcher_less_replace_status_precedes_handle_response_in_both_orders`, `response_matchers_do_not_break_the_phase_order`, `matcher_less_entries_move_last_after_the_phase_order`, `non_interleaved_replace_status_order_is_unchanged`, `forward_auth_canonical_handler_stays_first_and_phase_order_follows`), golden fixtures `reverse_proxy_replace_status_interleaved_{plain,matchers,mixed}`, `reverse_proxy_replace_status_noninterleaved`, `forward_auth_replace_status_interleaved` (`local_fixtures_have_exact_output_and_validate`) — `T-CONF-058`.

## DIV-0100 — Revocation checking (OCSP stapling, CRLs) is out of scope
- Status: out-of-scope
- Area: TLS
- Caddy behaviour: certmagic staples OCSP responses for managed certificates by default (fetch from the certificate's responder, cache, refresh before `nextUpdate`, persist, honour `disable_ocsp_stapling`/`must_staple`/`ocsp_overrides`). Caddy v2.11.9 has **no CRL support**: there is no CRL config surface, no CRL fetch and no CRL-based verifier anywhere in the tree.
- caddy-rs behaviour: the TLS crate contains the OCSP machinery built earlier (DER request/response handling, AIA/Must-Staple parsing, cache, refresh window, exponential backoff, `CertifiedKey::ocsp` attachment) and the server fetches/staple-refreshes through a live transport. It is **not a product goal**: response signatures are not verified, staples are memory-only, and the feature is left as-is rather than completed. CRLs are not implemented — an extension would be required, since there is no Caddy surface to mirror. Operators who need revocation control should disable stapling (`apps.tls.disable_ocsp_stapling`) and rely on short certificate lifetimes plus their CA's/OS's own revocation data.
- Rationale: the industry has moved away from client-side OCSP. Let's Encrypt ended its OCSP responder in 2025 and now publishes CRLs, the CA/Browser Forum no longer requires OCSP, browsers largely dropped soft-fail OCSP decades ago (Chrome uses CRLSets, Firefox CRLite/CRLs), and short-lived certificates shrink the revocation window that revocation checking existed to close. Paying to complete OCSP signature verification and to invent a CRL surface that Caddy does not have would buy little for this project's deployments.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/ocsp/tests.rs`, `crates/tls/src/tls_server.rs` (`resolver_exposes_stapled_certificates`) — kept green as existing behaviour, not as a supported product claim.

## DIV-0101 — Active health checks are generation-scoped; several advanced fields remain unsupported
- Status: open
- Area: Proxy / Server
- Caddy behaviour: `reverse_proxy.health_checks.active` runs background probes from handler provisioning (`modules/caddyhttp/reverseproxy/healthchecks.go`) for static upstreams only; each handler owns its active health state. Supported fields: `uri`/deprecated `path`, `method`, `headers`, `body`, `interval`, `timeout`, `passes`, `fails`, `max_size`, `expect_status` (exact code or class), `expect_body` (Go RE2 regular expression), `follow_redirects`, and alternate `upstream`/`port` targets. Probes update active health independently of passive `max_fails`/`fail_duration`; `Upstream.Available()` combines both, so routing skips unhealthy upstreams. The admin `/reverse_proxy/upstreams` payload exposes only `address`, `num_requests` and `fails` (no health field). Dynamic upstreams are silently skipped by active checks.
- caddy-rs behaviour: active checks run end to end. The server runtime starts one scheduler per handler when a generation is successfully applied and stops it when that generation is replaced or the runtime shuts down (generation-scoped, no task leaks across reloads; a failed reload keeps the previous generation's checkers). Probes implement `uri`/`path`, `method`, `headers`, `body`, `interval`, `timeout`, `passes`, `fails`, `max_size`, `expect_status` and `expect_body` (shared linear-time `regex` engine, Caddy `max_size` LimitReader semantics, status evaluated first). Probe bodies and configured header values expand Caddy's global placeholders with `ReplaceKnown` (unknown JSON braces preserved, including known placeholders nested inside JSON), header names and the special `Host` value with `ReplaceAll`, using the `env.*`/`system.*`/`time.now.unix`/`time.now.unix_ms` subset plus `{http.reverse_proxy.active.target_upstream}`; a configured `Host` also overrides the request authority, probes send an implicit Content-Length and no implicit Content-Type, and redirects are not followed by default (Caddy's `ErrUseLastResponse`). Unsupported global placeholders (`file.*`, formatted `time.now.*`) are preserved rather than expanded. Results flip `Upstream.healthy`, so load-balancer selection skips failed upstreams and resumes on recovery. Unsupported Caddy fields fail loudly at configuration load: `port` (`PROXY-HEALTH-PORT`), alternate `upstream` target (`PROXY-HEALTH-UPSTREAM`) and `follow_redirects` (`PROXY-HEALTH-REDIRECT`); active checks with dynamic/placeholder upstream dials are rejected loudly (`PROXY-DYNAMIC-UPSTREAM-HEALTH`) where Caddy silently does not run them; `expect_body` patterns using non-RE2 constructs (look-around/backreferences) are located errors. `GET /reverse_proxy/upstreams` keeps Caddy's payload (no health field), so active health is observable through routing; passive health state remains per handler (Caddy shares it globally).
- Rationale: running active checks is required for parity; unsupported Caddy fields and unsupported regex constructs are loud rather than silently approximated; health state is a routing signal, not an admin wire field in Caddy either.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_active_health.rs` (generation lifecycle, unhealthy skip + recovery, expect_status/expect_body/timeout failures, no-config no-probe, reload/shutdown leak checks, loud config errors), `crates/proxy/src/health.rs` (`expect_body` parsing/match/max_size, probe body/header placeholder expansion, status-first evaluation, `fails`/`passes` thresholds, 1 MiB body bounded by `max_size`, default no-follow redirects, scheduler unit tests).

## DIV-0102 — `http.handlers.acme_server` is implemented for http-01; persistence, dns-01/tls-alpn-01 and some error details diverge
- Status: open
- Area: HTTP / TLS / Caddyfile
- Caddy behaviour: `acme_server [<matcher>] { ... }` (`external/caddy/modules/caddypki/acmeserver/caddyfile.go:45`) accepts exactly `ca <id>`, `lifetime <duration>`, `resolvers <address...>`, `challenges <type...>`, `allow_wildcard_names`, `allow { domains ...; ip_ranges ... }`, `deny { domains ...; ip_ranges ... }` and `sign_with_root`; it emits the `http.handlers.acme_server` handler (`modules/caddypki/acmeserver/acmeserver.go:44-110`: `ca`, `lifetime` as integer nanoseconds, `resolvers`, `challenges`, `policy`, `sign_with_root`) and also returns a `pki.ca` configuration value that `buildPKIApp` merges into `apps.pki`, with a CA already defined by the global `pki` option taking precedence (`caddyconfig/httpcaddyfile/pkiapp.go:233-248`). Challenge names and CA IDs are validated at provision time, not during adaptation. The directive is ordered last among handler directives (`caddyconfig/httpcaddyfile/directives.go:99`), after `file_server`. Eight upstream `acme_server_*` fixtures pin the JSON. At runtime the handler mounts smallstep's ACME API under `<path_prefix><ca>/` (default `/acme/local/...` for the `local` CA), with smallstep's bbolt database, all three challenges by default, `key-change` wired to smallstep's `NotImplemented` (501), and the other endpoints POST-only (chi answers 405 with `Allow: POST`; directory/new-nonce answer GET/HEAD only). smallstep normalises a policy rule `*.example.com` to a one-label constraint (`.example.com`) and rejects `.example.com`, `*example.com`, `a*.example.com` and empty-label rules at provision; DNS identifiers are validated with `idna.Lookup.ToASCII` (so `a.example.com:80`, `::1`, `_x.example.com`, `-bad.example.com` are `malformed`) and wildcard identifiers are offered when the challenge policy permits. Certificate responses are `application/pem-certificate-chain` with **leaf + intermediate** (the root is the client trust anchor); `sign_with_root` returns **leaf + root**.
- caddy-rs behaviour: the Caddyfile adapter still emits Caddy v2.11.9's exact JSON for every accepted form; all eight upstream `acme_server_*` fixtures (`crates/config/tests/fixtures/upstream/`) are adapt-identical to the v2.11.9 oracle binary. `ca` also contributes Caddy's `apps.pki` entry (`{"<id>": {}}`) when the global `pki` option does not define that ID; nested uses match Caddy (`handle`/`handle_errors` drop the `pki.ca` value, `route` rejects it, `caddyconfig/httpcaddyfile/builtins.go:818`). Unknown suboptions, stray arguments, malformed `allow`/`deny` rules, invalid durations and `acme_server` with `ca` inside `route` are located errors naming the construct. `http.handlers.acme_server` is registered and implemented (`crates/http/src/acme_server.rs`): it serves the Caddy URL shape (`<path_prefix><ca>/directory`, `/new-nonce`, `/new-account`, `/new-order`, `/account/<id>[/orders]`, `/order/<id>[/finalize]`, `/authz/<id>`, `/challenge/<az>/<id>`, `/certificate/<id>`, `/revoke-cert`, `/key-change`), with Caddy's `GET`/`HEAD` directory, `GET` 204 / `HEAD` 200 `new-nonce`, POST-only remaining endpoints (405 with one `Allow` header per accepted method), flattened RS256/ES256 JWS verification (unprotected header forbidden, single-use bounded nonces, protected `url` checked), RFC 8555 problem documents with smallstep's status codes, bounded FIFO state for nonces/accounts/orders/authorizations, a real bounded `http-01` GET of the key authorization (never marked valid without it), CSR signature + exact order-identifier verification at finalize, issuance through `InternalIssuer::sign_external_spki_with` (configured `lifetime` clamped to [5 min, 365 d] and to the issuer's validity; `sign_with_root` selects the root), and `application/pem-certificate-chain` responses with leaf + intermediate (leaf + root with `sign_with_root`), matching the oracle. Policy rules are parsed as exact names or one-label `*.` wildcards and are enforced for both allow and deny; `.example.com`, `*example.com`, `a*.example.com`, bare `*` and empty-label rules are located load errors, so a rule can never be silently ineffective. `dns` identifiers are strict hostnames (ASCII alphanumerics/hyphen labels, no colon/port/IPv6 literal/underscore/empty label, ≤63-byte labels, ≤253 bytes), `ip` identifiers are parsed as IP addresses, and cross-account access to orders/authorizations/challenges/certificates/revocation is rejected. ACME request bodies are collected by the handler with a 64 KiB bound while streaming, so adding `acme_server` no longer forces router-wide body buffering (the previous 64 KiB check only ran after buffering, and `max_request_body_size` defaults to unlimited). `Host`/`path_prefix` JSON fields are supported.
- Residual: (1) only `http-01` is offered. A configuration that explicitly lists `dns-01` or `tls-alpn-01` (or non-empty `resolvers`, which only exist for dns-01) fails at load/provision with a located error, and wildcard identifiers are rejected at new-order with `rejectedIdentifier`. Caddy offers all three challenges by default and smallstep's wildcard flag is only effective together with a name policy (observed: the oracle accepts `*.example.com` orders without `allow_wildcard_names`); caddy-rs is deliberately stricter and requires dns-01, which it does not implement. (2) ACME state is in memory for one configuration generation: accounts, orders, authorizations and certificate material are not persisted across reloads (Caddy uses a bbolt database under `acme_server/<ca>`), and the bounded stores evict the oldest entries under sustained load. (3) revocation is recorded in memory only (no OCSP/CRL responder) and must be signed by the owning account key; a JWS signed with the certificate key is rejected 403 instead of being verified, and duplicate revocation returns `alreadyRevoked`. (4) `key-change` returns 501 like upstream smallstep's `NotImplemented` route, but with the standard `malformed` type rather than smallstep's mislabelled `rejectedIdentifier`. (5) only RS256/ES256 JWS algorithms are supported; ES384/ES512/RS384/RS512/PS*/EdDSA are rejected with `badSignatureAlgorithm` (Caddy accepts them). (6) `new-order` rejects `notBefore`/`notAfter` with `malformed` rather than honouring them. (7) the `ca` ID lookup now matches Caddy's `GetCA`: `local`/empty is provisioned on demand and an undeclared id fails provision with "no certificate authority configured with id: <id>" (`T-TLS-088`). The provision-time lifetime rule is also Caddy's: the leaf `lifetime` must be strictly shorter than the authority's `intermediate_lifetime` (default 7d), compared on the raw configured value, with an operator-supplied intermediate exempt. What remains: configured `apps.pki` intermediate lifetimes are not applied to the ACME issuer itself (it signs with the internal CA defaults), so a configured `intermediate_lifetime` is honoured by the rule but not by the issued chain; `intermediate_lifetime <= 0` is rejected by core validation where Caddy defaults it to 7d. (8) unknown order/account/certificate IDs and unknown ACME paths return 404 `malformed`, where smallstep wraps missing database rows as 500 `serverInternal`. (9) certificate subjects use the internal CA's `CN=<first identifier>` policy and do not copy the CSR's subject. (10) the directory omits `meta` when empty, matching the v2.11.9 oracle. (11) DNS identifier/rule syntax is deliberately stricter than smallstep's `idna.Lookup.ToASCII` in two cases: non-ASCII (IDNA) names are rejected because this build has no IDNA implementation, and empty labels (`a..example.com`) are rejected even though the oracle accepts that order (observed 201). Both are fail-closed; they cannot make a configured deny rule fail open. (12) order `notBefore`/`notAfter` are informational: finalize issues with the configured `lifetime` measured at finalize time (the normal immediate-finalize case is within seconds of the advertised window). (13) each ACME handler instance owns an `InternalIssuer` over the shared `pki/authorities/<ca>` files, so two servers in one generation that both mount `acme_server` for the same CA can each cache their own CA snapshot if their very first issuance races; the persisted material is last-writer-wins. A shared per-generation issuer cache is the follow-up. (14) CA material is rooted at the generation data/storage root (the same root automatic HTTPS uses), not at `$CADDY_RS_DATA_DIR`, which the server runtime does not yet consult; a non-filesystem storage backend (none is registered today, but embedders can select one) fails closed with a located router error instead of writing CA material to a relative `.caddy-rs` path.
- Rationale: a real ACME client (certbot, lego, Caddy, acme.sh) can obtain a certificate from caddy-rs's internal CA and validate it, which is the operational purpose of the module. The remaining gaps are advertised or fail closed: unsupported challenge policies and `resolvers` are located load errors, wildcards are explicit ACME errors, `*.` policy rules are enforced with the oracle's one-label semantics, and state persistence/revocation are documented rather than silently approximated.
- Tracking: T-COMPAT-003
- Residual:
  (15) Forwarded-origin selection is gated by the `trusted_proxy` request variable, which is configuration-level trust rather than a request-integrity proof: the server normally derives it before routing from the transport peer (or an accepted PROXY-protocol header) against `trusted_proxies`/`trusted_proxies_unix`, but operator `vars`/`map` handlers can also write it, including values expanded from request placeholders such as `{http.request.header.*}` (Caddy parity; the module docs now say this instead of claiming forwarded headers are not request influenceable). Without that policy valid forwarded values are ignored, while malformed `X-Forwarded-Proto`/`X-Forwarded-Host` values are still rejected even from untrusted peers. `X-Forwarded-Proto`/`X-Forwarded-Host` are a caddy-rs extension (Caddy's `acme_server` has no forwarded-origin option). PROXY-protocol listeners replacing `remote_addr` with a header-supplied source remains a cross-cutting residual owned by the forwarded-header security review.
  (16) `T-TLS-087` hardens the forwarded-origin trust anchor's documentation and diagnostics. The `trusted_proxy` variable is configuration-level trust: operator `vars`/`map` handlers can write it, including from request placeholders, so the handler consumes a value it cannot prove came from the transport. caddy-rs emits load-time warnings that Caddy does not: naming the server and configured range when `trusted_proxies` trusts every address (`all`, `0.0.0.0/0`, `::/0`), and naming the server and exposed listener when a `proxy_protocol` listener wrapper is configured on a non-loopback address. These are warnings, not located errors, because the trust is explicitly configured and Caddy accepts it; with no policy and no wrapper `trusted_proxy` is false and forwarded values are ignored. The resolved decision is observable per request as `{http.vars.trusted_proxy}` and `{http.vars.client_ip}`. F-4/F-5 operator obligations (the trusted proxy must overwrite/strip client-supplied `X-Forwarded-Proto`/`X-Forwarded-Host`, forward the client-facing scheme, and not synthesize malformed values) are documented in `docs/FEATURES.md` and the module docs.

- Tracking: T-COMPAT-003
- Test: `crates/config/tests/acme_server.rs` (adapter: ten tests, eight upstream fixtures semantic-identical, located errors), local fixtures `crates/config/tests/fixtures/local/acme_server_{default,options,implicit_ca,nested_handle}`, `crates/config/tests/local_adapt.rs`; `crates/tls/src/acme/csr.rs` unit tests (CSR parse/verify for P-256/P-384/RSA, SAN extraction, tampered/truncated/oversized rejection, non-DNS/IP SAN flag), `crates/tls/src/internal_ca.rs` unit test (`acme_signing_uses_intermediate_or_root_and_returns_the_chain`, asserting the two-block leaf+intermediate / leaf+root chains); `crates/http/src/acme_server.rs` unit tests (directory shape + new-nonce headers/HEAD, nonce single-use and bound, ES256+RS256 accept, bad nonce/url/signature/algorithm/content-type reject, exact/`*.` allow+deny policy semantics and located rule errors, http-01 success/wrong-key-authorization/connection-failure, real hyper transport + body cap, streaming 64 KiB body bound, finalize-before-ready, CSR/order mismatch, cross-account order/authz/challenge/finalize/certificate/revoke rejection, `onlyReturnExisting` + deactivation, malformed dns identifiers, 405/Allow methods, two-block certificate chain (and leaf+root with `sign_with_root`) for the CSR key, revoke + order list + key-change 501, located config errors), `crates/http/tests/acme_server.rs` (real router: directory/pass-through, missing/non-filesystem data root and dns-01/resolvers fail closed); `tools/compat/adapt_conformance.py` classifies all eight `acme_server_*` as `pass`. `crates/server/src/runtime.rs` `forwarded_trust_warning_tests`, `crates/server/tests/acme_server_forwarded.rs` (`operator_header_driven_vars_makes_the_trust_gate_request_influenceable`, `server_trusted_proxies_gate_the_acme_forwarded_origin`), `crates/proxy/src/trusted_proxies.rs` (`permissive_ranges` retains the configured spelling).
Forwarded external origin (T-TLS-086): origin selection for `X-Forwarded-Proto`/`X-Forwarded-Host` requires the server-level trusted-proxy policy to mark the peer trusted (`apps.http.servers.<name>.trusted_proxies`, surfaced as the `trusted_proxy` request variable); valid forwarded values from an untrusted peer are ignored. Validation applies regardless of that policy: `X-Forwarded-Proto` must be exactly `http` or `https` (case-insensitive, surrounding ASCII whitespace trimmed) and `X-Forwarded-Host` must be a strict `host` or `host:port` (no scheme, path, query, fragment, userinfo, whitespace, control characters or percent-encoding; no empty value; no comma lists or duplicate header lines; bounded lengths; IPv6 literals only in brackets and validated), with an explicit port preserved; malformed values are ACME `malformed` even from untrusted peers. The forwarded origin replaces the connection scheme and request `Host` in the directory/account/order/authz URLs and in the JWS protected `url` comparison; a configured `host` remains authoritative over `X-Forwarded-Host`, and a trusted forwarded scheme applies even when `host` supplies the authority. The headers never affect routing, account/order ownership, certificate identifiers or the `http-01` fetch target.

  Direct requests keep the historical `https` scheme, but their authority is now validated with the same strict grammar; an authority outside it (a trailing-dot FQDN, percent-encoding, userinfo, path/query/fragment, an empty label, leading/trailing `-`, or an unbracketed IPv6 literal) is ACME `malformed` instead of being interpolated raw — a deliberate fail-closed divergence from Caddy v2.11.9 for invalid authorities, while valid direct authorities produce the same URL. The JWS `url` binding also now uses the configured `host` when set even if the request `Host` differs (previously the binding used the request `Host` while the directory used the configured host, so a differing configured `host` was unbindable) — Caddy/smallstep parity, but a behaviour change for configurations with `host` set.
## DIV-0103 — Upstream PROXY protocol v1/v2 is implemented; the per-client authority encoding differs
- Status: open
- Area: Proxy
- Caddy behaviour: `transport.http.proxy_protocol` (`"v1"`/`"v2"`, Caddyfile `transport http { proxy_protocol v1|v2 }`) writes a PROXY protocol header on every new upstream TCP connection before the HTTP request and before the TLS handshake (`modules/caddyhttp/reverseproxy/httptransport.go`). The source is the resolved `client_ip` request context (IP-only, so the source port is 0) and the destination is the all-zero address of the same family because the original destination is not knowable; Caddy also encodes the client AddrPort into the request host so HTTP/2 pools connections per client (issue #7529). Missing client info is a dial error, and Unix-socket upstreams get the header written over the socket.
- caddy-rs behaviour: JSON `transport.proxy_protocol` accepts `v1`/`v2`; unknown values and non-strings are located configuration errors, and the Caddyfile `transport http { proxy_protocol v1|v2 }` form now adapts to Caddy's exact `"proxy_protocol"` JSON (verified byte-identical against the real v2.11.7 adapter, with a local fixture). The connector writes the exact v1 text / v2 binary header (signature, PROXY command, TCP4/TCP6 family, zero destination address and zero ports, no TLVs) on every new upstream connection before the TLS ClientHello, HTTP/1.1 bytes or h2c preface, so TLS/h2/h1/retries and dynamic dials keep working; the source is the resolved `client_ip` variable (port 0) with peer-address fallback and a located per-request error when absent. Differences: (1) because Rust's `http::Uri` rejects percent-encoded authorities, the per-client pool key is the URI-valid marker `pp-<hex-ip>-p0.<host>` instead of Caddy's `url.QueryEscape(addr->host)`, so the HTTP/2 `:authority` sent upstream differs from Caddy's escaped string (client identity and pool separation are preserved); (2) Unix-socket upstreams combined with `proxy_protocol` are rejected loudly instead of writing the header over the socket; (3) active health checks use plain upstream URLs and send no PROXY header, matching Caddy's active checker (which uses the default HTTP client rather than the configured transport).
- Rationale: sending PROXY protocol is required for load-balancer chains that expect it; JSON and Caddyfile adaptation match Caddy, while the authority encoding and the Unix/FastCGI rejections are documented rather than silently approximated.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/tests/proxy_protocol_upstream.rs` (v1/v2 real-socket header + ordering, client-IP-variable source, IPv6, TLS-before-ClientHello, h2c-before-preface, retry connection, located config errors, Unix/FastCGI rejection), `crates/proxy/src/client.rs` unit tests (authority marker round-trip, exact header bytes), local adapter fixture `reverse_proxy_transport_proxy_protocol`; listener direction remains DIV-0088.

## DIV-0104 — `rate_limit` is a caddy-rs extension (Caddy has no built-in rate limiter)
- Status: accepted
- Area: HTTP handlers
- Caddy behaviour: Caddy v2.11.9 has no `http.handlers.rate_limit` module and no `rate_limit` Caddyfile directive; rate limiting is provided by the external `github.com/mholt/caddy-ratelimit` plugin, whose zone/events/window configuration is not part of the core Caddy API. caddy-rs does not claim configuration or runtime parity with that plugin.
- caddy-rs behaviour: implements a caddy-rs-only JSON handler `http.handlers.rate_limit` (`{"handler":"rate_limit","rate":"10r/s","burst":20,"key":"{http.request.remote.host}","max_keys":10000,"status_code":429,"headers":{...},"body":"..."}`): per-key token buckets refilled from a monotonic clock, placeholder-expanded keys (peer host by default), a bounded bucket map with idle-bucket eviction and fail-closed new keys at capacity (`max_keys` defaults to 10000; an expanded key longer than 256 bytes is stored as `sha256:<64 lowercase hex>` so attacker-controlled expansions cannot blow up the map key space), a 429 response with an integer `Retry-After` (status/body/headers configurable), and non-terminal middleware semantics (allowed requests continue to the next handler). The limiter is process-local, does not persist across reloads, does not distribute across instances, and keys on the peer address only (no trusted-proxy/`X-Forwarded-For` derivation unless the key expression reads a header). The caddy-rs-only Caddyfile directive `rate_limit <rate> [burst] { burst \| key \| max_keys \| status_code \| headers \| body }` adapts 1:1 onto these handler fields (ADR-0011 §4): the documented `(caddy-rs-ratelimit)` snippet adapts to `{"handle":[{"handler":"rate_limit","rate":"100r/s","burst":200,"max_keys":10000}]}`, an omitted field keeps the handler default above, and `caddy-rs adapt` therefore shows exactly what the directive enables. The community module's `zone`/`events`/`window` form and unknown options remain unsupported: they are located errors naming the extension, `DIV-0104` and [`docs/operations/RATE-LIMITING.md`](../operations/RATE-LIMITING.md), never translated or emulated.
- Rationale: rate limiting is operationally important but was not a core Caddy feature; modelling it as an explicit extension keeps the compatibility contract honest instead of pretending it is a Caddy module. Token-bucket admission with bounded state avoids unbounded per-client memory and gives deterministic, testable behaviour.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/rate_limit.rs` (unit tests with `ManualClock`: burst/refill/`Retry-After`, header and vars keys, default remote-host key, eviction bound, fail-closed capacity, long expanded keys hashed to `sha256:<64 hex>` (`very_long_key_is_hashed`) while short keys stay raw, 50-way tokio concurrency, located config validation, rate/duration parsing) `crates/http/tests/rate_limit.rs` (real router: 200s then 429s then refill, configurable response, matcher-scoped routes, key isolation, routed concurrency) and `crates/config/tests/rate_limit.rs` (the ADR-0011 `(caddy-rs-ratelimit)` snippet adapts to the exact hand-written handler JSON, every option maps 1:1, omitted fields keep the handler defaults, both `burst` forms and their double specification, `stock_compat` true/false identity, and located errors for bad rate/integers, unknown options and the community `zone`/`events`/`window` form naming `DIV-0104` and `docs/operations/RATE-LIMITING.md`). The operator page is [`docs/operations/RATE-LIMITING.md`](../operations/RATE-LIMITING.md).

## DIV-0105 — S3-compatible storage is a caddy-rs extension, not a Caddy core module
- Status: accepted
- Area: TLS
- Caddy behaviour: Caddy v2.11.9 ships only the `file_system` storage module; S3-backed storage comes from community plugins (commonly `caddy.storage.s3`) configured as a storage module object with endpoint/bucket/region/prefix/credentials.
- caddy-rs behaviour: caddy-rs adds an S3-compatible backend selectable through the top-level `storage` module (`{"module":"s3", ...}`): SigV4 signing (shared with Route 53), path-style or virtual-host addressing, GET/HEAD/PUT/DELETE, ListObjectsV2 with continuation pagination, certificate (`certificates/<issuer>/<name>.{crt,key,json}`) and ACME-account (`acme/...`) persistence, explicit or environment AWS credentials, and TLS through the existing hyper transport. Locks are simplified conditional-PUT `locks/<name>` objects with no expiry/refresh/multi-process coordination; multipart uploads, region redirect/retry and the plugin's full settings surface are not implemented.
- Rationale: pluggable storage is operationally important; implementing it as a tested caddy-rs extension keeps Caddy-core storage module parity honest instead of silently claiming a non-core module.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/s3/tests.rs` (scripted transport: settings/redaction/located errors, PUT/GET/HEAD/DELETE round-trip, 404→None, idempotent delete, ListObjectsV2 pagination, path-style and virtual-host targets, lock conditional PUT/412/unlock, certificate and account trait round-trips, typed errors), shared SigV4 AWS vector in `crates/tls/src/sigv4.rs`.

## DIV-0106 — Client-certificate placeholders are wired for HTTP/1.1 and HTTP/2
- Status: fixed
- Area: TLS/HTTP
- Caddy behaviour: `{http.request.tls.client.*}` exposes the presented client certificate: `fingerprint`, `public_key`, `public_key_sha256`, `certificate_pem`, `certificate_der_base64`, `issuer`, `serial`, `subject`, and `san.dns_names`/`san.emails`/`san.ips`/`san.uris` (whole lists and indexed `.N`). With no client certificate Caddy substitutes a dummy empty certificate, so known fields expand to empty; unknown client fields are not recognised. Caddy v2.11.9 has no `*In` variants (`external/caddy/modules/caddyhttp/replacer.go`, `caddyhttp/app.go`).
- caddy-rs behaviour: the server captures `peer_certificates()[0]` after the TLS handshake, parses it with the TLS crate's `ClientCertificateInfo`, records the listener's client-auth verification mode, and attaches an `http::ClientCertificate` to the internal request. The HTTP replacer implements every Caddy v2.11.9 suffix with the same decimal serial, lowercase-hex fingerprint/public-key values, PEM/base64 certificate encoding, SAN list/index semantics and dummy-empty missing-certificate behaviour, for HTTP/1.1 and HTTP/2. The HTTP/3 path has no client-certificate authentication/peer-certificate exposure yet, so placeholders expand empty there.
- Rationale: request-context wiring belongs to the server; the TLS-side parser and placeholder mapping stay in their crates, with a TLS-neutral type in `caddy-rs-http` to avoid a crate cycle.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/placeholders.rs` client-certificate unit tests; `crates/server/tests/http_client_auth.rs` real-TLS mTLS, missing-certificate and unverified-`require` tests.

## DIV-0107 — `expression` matcher implements a documented CEL subset
- Status: open
- Area: HTTP matchers
- Caddy behaviour: Caddy v2.11.9 compiles `http.matchers.expression` with cel-go. `{placeholders}` are expanded to the `ph(req, name)` replacer function; the environment exposes the `req` variable plus CEL matcher libraries (`host()`, `path()`, `method()`, `header()`, `query()`, `client_ip()`, `path_regexp()`, `tls()`, `vars()`, …), macros/comprehensions, strings/math/lists extensions, timestamps and optional types. Provisioning type-checks the program and rejects a non-bool result. Missing placeholders follow replacer semantics (headers/cookies/queries empty, vars/unknown null). Runtime evaluation errors log and set a matcher error. The Caddyfile form `@name expression <CEL>` keeps raw tokens for multi-token expressions and the cleaned single token otherwise.
- caddy-rs behaviour: a hand-written lexer/parser/type-checker/evaluator implements a documented subset without a CEL dependency: boolean literals/`!`/`&&`/`||`/parentheses; string literals with escapes (CEL backtick raw strings are rejected by Caddy v2.11.9 itself — the v2.11.9 oracle reports a CEL parse error for `` `402` `` — so caddy-rs rejects them too, with a syntax-error message), integer and bool literals; `==`/`!=` over strings, ints and bools; `<`/`<=`/`>`/`>=` over strings and ints; `in` over homogeneous list literals; Caddy placeholders (`{http.request.*}`, `{http.vars.*}`, `{http.error.*}`, headers/cookies, unknown placeholders) plus convenience aliases (`request.method`, `request.host`, `request.path`, `request.uri.*`, `request.remote_ip`, `request.header(...)`, `request.cookie(...)`, `vars.<name>`, `tls.enabled`/`tls.handshake_complete`). Unknown identifiers, malformed syntax, non-bool top-level expressions, static type mismatches and mixed-type lists are located configuration errors at load. Missing values match observed Caddy semantics: headers/cookies/queries empty, unset vars/unknown placeholders null. The Caddyfile adapter emits Caddy's exact JSON for named expression matchers (multi-token bare string with raw-token quoting, single-token object with the matcher name), golden-verified against real Caddy v2.11.9.
- Rationale: full cel-go is not available offline; the hand-written subset covers status/error routing and common request-field routing with fail-closed configuration, while keeping the hot path allocation-light (pre-parsed AST, short-circuiting, borrowed strings where possible).
- Residual divergences: CEL matcher functions/macros/comprehensions, regex/`matches()`, timestamps/durations, doubles/bytes/uints, optional types, ternaries, list indexing/nested lists, Caddy's `req` object and `ph()` are unsupported and rejected loudly; string placeholder interpolation inside string literals is unsupported; TLS certificate/cipher attributes parse as known `tls.*` names but evaluate as missing because the HTTP engine carries only a TLS boolean; dynamic placeholder values are coerced for integer/boolean comparisons (required by `{http.error.status_code}`) whereas Caddy's cel-go can return `no such overload` (HTTP 500) when a string-valued placeholder is compared to an int; the `request.*` aliases are caddy-rs conveniences, not Caddy CEL names (Caddy-compatible expressions use placeholders); expression syntax errors are bucketed as parse errors like Caddy's CEL parse errors, so the oracle classifies both rejections as equivalent.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/expression.rs` (parser/type/missing-value unit tests), `crates/http/tests/expression.rs` (real router, per operator/type, headers/cookies/vars, missing values, located load errors, `handle_errors` status expressions), `crates/config/tests/matchers_adapt.rs` (named expression adaptation, golden-verified), `.scratch/logs/w18-expression/comparison4.txt` (16/16 identical results against the available Caddy oracle binary).

## DIV-0111 — Admin global option: block form adapted; `listen` ordering differs in emitted JSON
- Status: mitigated
- Area: Configuration
- Caddy behaviour: `admin [<address>|off] [{ enforce_origin; origins <hosts...> }]` (`options.go` `parseOptAdmin`). `admin off` rejects any further argument or block; an enabled endpoint without an address gets `localhost:2019`; unknown block parameters are errors. The emitted object is `{listen, enforce_origin, origins}` in struct order.
- caddy-rs behaviour: all four forms adapt to the same JSON values as `caddy adapt` v2.11.9 (`admin` alone and `admin <addr> { ... }` included), with the same located errors for `admin off` blocks, unknown parameters, extra arguments and an empty `origins`. `persist_config` stays unsupported (`T-CONF-055`). The only difference is key order inside the `admin` object (`enforce_origin` sorts before `listen`), because the adapter serialises object keys in sorted order; semantic JSON is identical.
- Rationale: key order is not significant in the configuration language (Caddy decodes by name), and matching struct order would require an order-preserving map across the adapter.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/upstream_adapt.rs` (`admin_global_option_block_adapts_like_caddy`, golden against `caddy adapt` v2.11.9, plus the four error cases).

## DIV-0110 — `log_skip`/`skip_log`/`log_name`/`log_level` are implemented
- Status: fixed
- Area: Logging
- Caddy behaviour: `log_skip [<matcher>]` adapts to a `vars` handler setting `log_skip: true` (`caddyconfig/httpcaddyfile/builtins.go` `parseLogSkip`); the access logger checks that variable after the route chain and suppresses the entry. `skip_log` is the deprecated alias and logs a warning. `log_name <names...>` adapts to a `vars` handler carrying the `access_logger_names` array (`parseLogName`), which replaces the server's per-host `logger_names` mapping for the request (`""` selects the base logger, an empty list selects none), and `log_level [<matcher>] <level>` adapts to `vars` with a case-insensitive `DEBUG`..`ERROR` value (`parseLogLevel`) that replaces the status-derived entry level. `log_name` never calls `NextBlock`, so a block is silently ignored; with no names Caddy emits `"access_logger_names":null`, which its JSON loader treats as unset.
- caddy-rs behaviour: all four directives are accepted and runtime-backed. The adapter emits Caddy's exact JSON, the `vars` handler publishes the post-routing decision into the per-request `AccessLogContext`, and the body-end emission point reads it after the handler chain. Order matches Caddy: `log_skip` first (metrics are still recorded and the response is unchanged), then the per-server host policy (a skipped host never logs, matching `shouldLogRequest` running before the handler chain), then an explicit `access_logger_names` array in place of the host mapping, then a valid `log_level` in place of the status-derived level. `logging.logs[].include`/`exclude` are evaluated against each entry's logger name, so a log dedicated to a named access logger receives `log_name` entries. Upstream `log_level*.caddyfiletest` fixtures: 3 exact JSON matches, 3 expected errors.
- Rationale: a logging directive that silently fails to suppress, rename or re-level entries is worse than a load error; the plumbing is complete end to end and each path has a real-server test.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/log_name_log_level_adapt.rs` (exact v2.11.9 JSON, path/named-matcher sort order, invalid-level/argument/block errors), `crates/config/tests/log_skip_adapt.rs`, `crates/server/tests/http_log_vars.rs` (skip/name/level, host-mapping precedence, skipped-host gating, sink threshold, Caddyfile end to end), `crates/server/tests/http_log_skip.rs`, `crates/admin/src/logging_config.rs` (`named_access_logger_targets_are_kept_and_route_by_logger_name`), upstream `log_level.caddyfiletest`, `log_level_sort_paths.caddyfiletest`, `log_level_sort_named_matchers.caddyfiletest`, `log_level_fatal.caddyfiletest`, `log_level_invalid.caddyfiletest`, `log_level_block.caddyfiletest`.

## DIV-0112 — Caddyfile adapt-mode system (`--adapt-mode`)

- Status: accepted (caddy-rs extension)
- Area: Configuration
- Caddy behaviour: `caddy adapt`/`validate`/`run` have no strictness modes; deprecated spellings are always accepted and Caddy always prints its deprecation warning (`skip_log` → `log_skip`, `basicauth` → `basic_auth`).
- caddy-rs behaviour: `adapt`, `validate` and `run` accept `--adapt-mode compatible|warn|strict` (default `compatible`). The mode gates a central deprecated-spelling table. `compatible` matches Caddy exactly for these aliases: accepted, Caddy's warning text emitted, emitted JSON identical to the replacement. `warn` is a superset of `compatible` (it will additionally report ambiguity constructs as the mode system grows). `strict` rejects a listed alias with a located `config.invalid` error naming alias and replacement, and never approximates an unimplemented capability. `log_skip` itself and every non-alias construct are unchanged in all modes. An unknown mode is a located `config.invalid` error naming the flag and the three values. The alias scan covers directive lists including `route`/`handle`/`handle_path`/`handle_errors` and `handle_response` bodies under `reverse_proxy`, `forward_auth` and `php_fastcgi`, recursively. The JSON adapter and the admin `/adapt` endpoint stay compatible (no mode).
- Rationale: operators migrating off deprecated spellings need a way to prove a configuration is alias-free before removing the compatibility surface, while default deployments keep byte-for-byte Caddy acceptance. Modes govern config-acceptance ambiguity only: `warn`/`compatible` never relax a security-relevant rejection (TLS, auth, trust/CORS, peer trust, crypto), and `strict` never approximates. There is no default-mode acceptance or warning divergence from Caddy; the divergence is the existence of the flag and `strict` rejecting configs Caddy accepts. This supersedes the earlier DIV-0110 statement that `log_skip` is rejected — it is implemented (T-HTTP-050).
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/log_skip_adapt.rs` (20 per-mode adapter tests incl. `handle_response` under all three parents), `crates/server/tests/http_log_skip.rs` (6 runtime sink tests), `crates/cli/tests/cli.rs` (mode flag plumbing, warning text, bounded `run` strictness). Oracle parity verified canonically for bare/matcher/`skip_log`/nested cases; raw JSON differs only in object key order.


## DIV-0113 — `transport http` compression defaults to off in caddy-rs
- Status: open
- Area: Proxy
- Caddy behaviour: the HTTP transport's `compression` defaults to **true**: unless `compression off` is set, Caddy adds `Accept-Encoding: gzip` to upstream requests and transparently decompresses gzip responses (`httptransport.go` sets `DisableCompression = !*Compression` only when the field is present, and Go's default is transparent compression).
- caddy-rs behaviour: the proxy never adds `Accept-Encoding`, never decompresses and never compresses, so an absent `compression` (Caddy's default `true`) behaves as `compression: false`. An explicit `compression: true` is rejected at load with a located error at `<handler>.transport.compression` carrying `PROXY-TRANSPORT-COMPRESSION`; `compression: false` is accepted because it matches what this build does.
- Rationale: no gzip codec is wired into the proxy body path, and silently changing response bytes on the way through would be worse than documenting the difference. Rejecting every transport that omits `compression off` would make the transport unusable, so the default difference is registered instead of refused.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/handler.rs` (`unsupported_transport_options_fail_loudly`: `compression: true` rejected, `compression: false` accepted; the upstream request path never adds `Accept-Encoding`).

## DIV-0114 — aws-lc-rs accepts P-521 certificate keys; P-521 key exchange and RSA-1024 stay rejected
- Status: accepted
- Area: TLS
- Caddy behaviour: certificate private keys may be RSA (Go accepts 1024-bit), ECDSA P-256/P-384/P-521 (SEC1 or PKCS#8) and Ed25519; Ed448, DSA, secp256k1, brainpool curves and encrypted PEM are rejected. `curves` accepts `x25519mlkem768`, `x25519`, `secp256r1`, `secp384r1`, `secp521r1`, and the default is `[x25519mlkem768, x25519, secp256r1]`.
- caddy-rs behaviour: the rustls provider is **aws-lc-rs** (rustls 0.23.46, aws-lc-rs 1.19): RSA-2048/3072/4096 (PKCS#1 and PKCS#8), ECDSA P-256 (SEC1 and PKCS#8), P-384, P-521 (SEC1 and PKCS#8) and Ed25519 certificates load and complete a real handshake. Encrypted PEM, Ed448, DSA, secp256k1 and other curves stay rejected with located errors that name the certificate entry (`apps.tls.certificates.load_files[i]`, its file paths, DNS names or `storage key …`), the detected key type, the algorithm OID and Caddy's wording where Caddy rejects the same key (`x509: unsupported elliptic curve`, `encrypted private keys are not supported`). `curves` accepts Caddy's four implemented names and defaults to Caddy's list, so `x25519mlkem768` is preferred and falls back to `x25519` for clients that do not offer it. Remaining differences: (1) `curves: ["secp521r1"]` is accepted by Caddy but is a located `TLS-POLICY` error here, because rustls' aws-lc-rs provider exposes no P-521 key-exchange group (its `ALL_KX_GROUPS` are X25519MLKEM768, SECP256R1MLKEM768, X25519, SECP256R1, SECP384R1, MLKEM768 and MLKEM1024); P-521 *certificate keys* are supported separately through signature schemes. (2) RSA keys below 2048 bits (and above 8192) are accepted by Caddy and rejected here with a located error that names the source entry, DNS names, detected modulus size and the provider's range: "RSA-1024 private keys are not supported by this build: rustls' aws-lc-rs provider requires RSA keys between 2048 and 8192 bits" (`T-TLS-090`), kept loud rather than silently substituted.
- Residual (T-TLS-092): the private-key format is decided by the **DER structure** (PKCS#8, SEC1 or PKCS#1) on every path, including the label-less certificate cache and storage loading, so a SEC1 or PKCS#1 body works even under a `PRIVATE KEY` label. Caddy/Go instead dispatches on the PEM label and rejects a mislabelled block; caddy-rs accepts it with a warning naming both the label and the detected structure, which is a deliberate leniency (a parsing gap in Go's model, not a security property — the same key bytes are handed to rustls in the right envelope). A block that is none of the three structures stays a located error naming the label and the `openssl pkcs8 -topk8 -nocrypt` / `openssl pkey` remedy. The certificate cache runs the same classifier: a certificate restored after a reload classifies its key from the DER structure before signing, so an unsupported key fails with the located message instead of the provider's bare one. Every key error names the source it came from — `apps.tls.certificates.load_files[i]` with the certificate and key paths for configured files, `storage key <key>` for storage, `certificate cache (<issuer>)` for a reloaded cache entry, `issued for <subject>` for a certificate obtained in that generation, and `stored certificate (issuer <id>)` for a certificate handed to the live resolver by the renewal store — and the located path and the certificate identity appear once. A key the classifier accepts but the provider still refuses (an RSA key with an invalid public exponent) keeps the same located, sourced message through the provider fallback. The source is carried on the loaded certificate, not persisted in the cache entry, so a cache-restored certificate names the cache and its issuer rather than the original storage key it was saved under (`T-TLS-094`, `T-TLS-095`).
- Rationale: aws-lc-rs is the only rustls provider with `SignatureScheme::ECDSA_NISTP521_SHA512`, so it is the only way to honour a P-521 certificate the way Caddy does; the same provider supplies the hybrid ML-KEM group Caddy already prefers by default. Loud rejection of the two remaining cases is better than silently dropping a configured curve or re-issuing a key with different parameters.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_tls.rs` (`rsa2048_pkcs1_certificate_completes_tls_handshake`, `rsa2048_pkcs8_certificate_completes_tls_handshake`, `rsa4096_certificate_completes_tls_handshake`, `ecdsa_p256_sec1_certificate_completes_tls_handshake`, `ecdsa_p256_pkcs8_certificate_completes_tls_handshake`, `ecdsa_p384_certificate_completes_tls_handshake`, `ecdsa_p521_sec1_certificate_completes_tls_handshake`, `ecdsa_p521_pkcs8_certificate_completes_tls_handshake`, `ed25519_certificate_completes_tls_handshake`, `second_load_files_certificate_with_unsupported_key_is_named`), `crates/tls/src/tls_server.rs` (`each_supported_curve_negotiates_when_configured_alone`, `default_curves_prefer_mlkem_and_fall_back_to_x25519`, `restricted_curves_are_negotiated`, `secp521r1_curve_fails_closed_and_unknown_names_fail_loudly`, `supported_private_key_matrix_builds_signing_keys`, `unsupported_private_key_types_are_classified`, `unsupported_key_error_names_certificate_source_and_dns_names`, `resolver_rejects_unsupported_key_types`, `cache_path_errors_name_the_source_once`, `provider_refusal_keeps_the_certificate_identity`), `crates/config/tests/tls_ciphers.rs` (`mlkem_curve_lands_in_the_connection_policy`, `caddy_accepted_but_runtime_unsupported_curves_fail_loudly`). `crates/tls/src/renewal.rs` (`publishing_a_refused_certificate_names_the_store_source`), `crates/server/src/error.rs` (`a_tls_error_is_not_printed_twice_through_its_own_source`), `crates/tls/src/key_type.rs` (`rsa_modulus_size_is_classified_against_the_provider_range`, `brainpool_curve_oids_are_classified_as_unsupported`), `crates/tls/src/tls_server.rs` (`rsa_1024_keys_are_rejected_with_located_errors`, `brainpool_curve_keys_are_rejected_with_located_errors`, `default_provider_kx_groups_are_caddys_default_curves`) (`T-TLS-090`).

## DIV-0115 — Non-dNSName subjectAltName entries are ignored when naming a certificate
- Status: accepted
- Area: TLS
- Caddy behaviour: certmagic's `fillCertFromLeaf` names a certificate from the subject commonName (deprecated but still accepted) plus every subjectAltName entry: `dNSName`, `iPAddress`, `rfc822Name` and `URI` (lowercased; a SAN equal to the raw CN is not duplicated). A certificate whose only identity is an IP, email or URI SAN therefore loads, and the names participate in certificate lookup.
- caddy-rs behaviour: `TlsCertificate` names include the subject commonName in addition to the subjectAltName `dNSName` entries, so CN-only certificates load and match their CN (`T-TLS-091`) and a CN+SAN certificate is served for both names, matching the pinned oracle. iPAddress (`[7]`), rfc822Name (`[1]`) and URI (`[6]`) GeneralNames are still not turned into names; a certificate with only such an entry and no CN is rejected at load with `certificate has no subjectAltName dNSName entries and no subject commonName`, where Caddy accepts it. The CN reader accepts Go's six subject string types (`UTF8String`, `PrintableString`, `IA5String`, `T61String` as Latin-1, `BMPString` as UTF-16BE, `NumericString`); any other value tag is a located error naming the tag. Known cosmetic differences from Go's parser: BMPString trailing NULs are not stripped and noncharacter code points are not rejected, and Printable/Numeric/IA5 character sets are not validated; name de-duplication is case-insensitive where certmagic compares raw strings, and names are ordered SAN-first where certmagic is CN-first (no consumer depends on the order).
- Rationale: caddy-rs' SNI resolver keys certificates by DNS name, and Caddy's IP/email/URI names do not participate in SNI selection either (they matter for IP site addresses, inventory and certificate placeholders). Rejecting a certificate that has only an IP SAN is a located, advertised load error rather than a silent approximation. Extending `certificate_names` to the remaining GeneralName forms is a residual gap outside `T-TLS-091`; it is listed here so the difference is not silent.
- Tracking: T-COMPAT-003
- Test: `crates/tls/src/tls_server.rs` (`cn_only_certificate_loads_and_matches_its_name`, `cn_and_san_certificate_prefers_san_and_keeps_cn_like_caddy`, `common_name_is_read_from_the_attribute_value_tlv`, `common_name_is_found_in_a_later_multi_rdn_subject`, `common_name_supports_go_string_encodings`, `non_string_common_name_value_fails_loudly`, `empty_subject_is_a_located_error_not_a_panic`, `malformed_subject_is_a_located_error_not_a_panic`, `cn_only_certificate_is_selected_over_tls`).

## DIV-0116 — Response matchers resolve in Caddy's declaration order
- Status: fixed
- Area: Configuration / adapter
- Caddy behaviour: `reverse_proxy`/`forward_auth`/`php_fastcgi` resolve the two response-matcher reference kinds in different phases. `replace_status` is appended to `Handler.HandleResponse` while `UnmarshalCaddyfile` walks the block, so it resolves its named matcher immediately and a reference to a matcher declared later fails adaptation with `no named response matcher defined with name '<name>'` (exit 1, located at the `replace_status` line). `handle_response` segments are only recorded and resolved in `FinalizeUnmarshalCaddyfile`, after the whole block is parsed, so a `handle_response` may reference a matcher declared later in the same block and adapts.
- caddy-rs behaviour: matches Caddy. A `replace_status` forward reference is a located `config.invalid` error naming the line and the matcher; a matcher declared before its use, and a `handle_response` forward reference, adapt byte-identically to Caddy v2.11.9 for all three directives.
- Rationale: accepting configuration the oracle rejects is fail-open, because the operator believes a response policy is in force that Caddy would have refused to load. Resolving each reference in Caddy's phase keeps the adapted JSON exact without narrowing valid configuration.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/response_matcher_order_adapt.rs` (forward `replace_status` rejected for `reverse_proxy`/`forward_auth`/`php_fastcgi`, forward `handle_response` accepted, oracle-exact valid order), golden fixtures `reverse_proxy_response_matcher_declared_before_use`, `reverse_proxy_handle_response_forward_reference`, `forward_auth_response_matcher_declared_before_use`, `forward_auth_handle_response_forward_reference`, `php_fastcgi_response_matcher_declared_before_use`, `php_fastcgi_handle_response_forward_reference` via `local_fixtures_have_exact_output_and_validate`.

## DIV-0117 — External private-key providers (PKCS#11/TPM/HSM/keystore) are unsupported
- Status: planned
- Area: TLS
- Caddy behaviour: Caddy v2.11.9 has no external private-key provider. `apps.tls.certificates` registers only `load_files`, `load_pem`, `load_folders`, `load_storage` and `automate`; the four file/PEM/storage loaders accept **PEM only** (`format` `""`/`"pem"`, `tls.X509KeyPair`, `.pem` bundles for folders; DER is rejected), `automate` triggers issuance instead, and certificates otherwise come from an ACME/internal issuer. No Caddy module, config field or loader names PKCS#11, a TPM, an HSM or an OS keystore; `github.com/google/go-tpm` is only an indirect module dependency in `go.mod` and no Caddy Go source imports it.
- caddy-rs behaviour: identical today. `apps.tls.certificates.pkcs11` is not a registered `TlsCertificateLoader`, so a configuration naming it fails at load with a located `unknown TLS certificate loader module` error at `apps.tls.certificates.pkcs11`, and no key leaves the process. ADR-0009 decides the extension: a PKCS#11 loader (`tls.certificates.pkcs11`) with a dedicated per-session signer thread, a blocking-pool handshake path, bounded queue and timeouts, and fail-closed token/PIN handling. Direct TPM ESAPI (`tss-esapi`) and OS keystores are rejected; the extension is JSON-only and loads externally issued certificates in phase 1.
- Rationale: an external key provider is a caddy-rs addition, not a Caddy parity claim. It changes the threat model (the key is non-exportable, but the process becomes a signing oracle), the handshake threading model (rustls' `Signer::sign` is synchronous) and the failure model (token loss and TPM clear), so it needs a decision record and a loud, tested refusal until T-TLS-096 lands.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs:1699` (`rejects_unknown_certificate_loader_with_located_error`) proves the unknown-loader refusal mechanism with a `load_bogus` key; the `pkcs11`-named refusal (`apps.tls.certificates.pkcs11` yields the located `unknown TLS certificate loader module` error) is an acceptance test of T-TLS-096 because this decision-record task does not change `crates/`. `crates/tls`/`crates/server` PKCS#11 handshake and failure-injection tests are tracked by T-TLS-096.

## DIV-0118 — `respond` rejects capabilities this build lacks and keeps two runtime gaps
- Status: accepted
- Area: CLI
- Caddy behaviour: `caddy respond` accepts `--debug` (debug-level internal logging), any integer
  `--status` (1xx is an interim response followed by a final 200; outside 100-999 Go panics per
  request), `unix/relative.sock`, `unixpacket/`/`unixgram/` Unix socket types, `fd/` activation,
  Unix socket permission suffixes, Go's full `text/template`, and a 10 KiB `MaxHeaderBytes`
  (16,000-byte request head -> 431). It ignores `LISTEN_FDS` for this command.
- caddy-rs behaviour: `--debug` exits 1 naming the flag; `--status` outside 200-999 (including
  1xx) exits 1 naming `--status` and the accepted range; relative Unix paths,
  `unixpacket`/`unixgram`, `fd/` and permission suffixes exit 1 naming `--listen`; template
  expressions other than `{{.N}}`/`{{.Port}}`/`{{.Address}}` exit 1 naming the body source.
  `tcp4/`, `tcp6/`, `udp/`, `udp4/` and `udp6/` are accepted and map to the same plain TCP
  listener Caddy ends up with; `respond` ignores `LISTEN_FDS`; the 10 s read-header and 30 s idle
  timeouts are applied. Residual runtime gaps: `max_header_bytes` is set to 10240 but acts as
  hyper's read-buffer cap (16,000-byte head -> 200 where Caddy returns 431; 12,000 and 20,000
  match), and control bytes in header values other than CR/LF become spaces where Go writes them
  through.
- Rationale: This build has no debug-level internal logging, no Go template engine, no interim
  response plumbing and no SOCK_SEQPACKET/SOCK_DGRAM HTTP listener. Silent acceptance would claim
  capabilities that do not exist; `respond` is a development tool, so a located error is a valid
  outcome, and the remaining runtime gaps are measured and registered rather than claimed as
  parity.
- Tracking: T-COMPAT-003
- Test: `crates/cli/tests/cli.rs` (`respond_rejects_debug_with_a_located_error`,
  `respond_rejects_interim_1xx_statuses_with_a_located_error`,
  `respond_ignores_systemd_socket_activation`,
  `respond_accepts_the_network_prefixes_caddy_drops`,
  `respond_sanitizes_header_values_and_drops_bad_names_like_caddy`,
  `respond_applies_caddys_read_header_timeout`,
  `respond_rejects_invalid_headers_arguments_and_templates`) and `crates/cli/src/respond.rs` unit
  tests; oracle evidence in `caddy-rs/docs/compatibility/T-CLI-008.md`.

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
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/cli/tests/cli.rs` `storage_rejects_an_unsupported_storage_module`,
  `storage_import_refuses_archive_keys_outside_the_root`,
  `storage_import_cleans_a_dot_prefixed_archive_key_into_the_root`,
  `storage_export_writes_a_sorted_tar_of_the_storage_tree`,
  `storage_import_writes_files_with_owner_only_mode`,
  `storage_help_matches_caddys_usage_and_flags`,
  `storage_requires_config_and_output_or_input_flags`

## DIV-0120 — caddy-rs parses, validates and builds Content-Security-Policy values where Caddy only stages an opaque header

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no CSP middleware. A `Content-Security-Policy` response header
  is staged by the generic `headers` handler (`modules/caddyhttp/headers/headers.go`) as the literal
  configured string: no directive parsing, no source validation, no nonce generation and no
  knowledge of `{csp.nonce}`.
- caddy-rs behaviour: `crates/http/src/csp.rs` parses a policy from JSON (`CspPolicy::from_json`,
  string or array source lists) or from a header value (`CspPolicy::parse_header_value`) into a
  `BTreeMap` of directive -> source list, validates directive names against the CSP Level 3 set and
  sources against the CSP grammar at load time (unknown directives, unknown keywords, `'none'`
  combined with other sources, non-ASCII/whitespace/`;` in sources, duplicate header directives,
  `report-uri`/`report-to` with anything but one value, and values on valueless directives) with
  located `InvalidConfig` errors such as `policy.script-src[1]`, and serializes deterministically
  (`to_header_value`: lexicographic directive order, single spaces, `; `, no trailing `;`).
  `{csp.nonce}` is a source token expanded per response by `expand_nonce` with `generate_nonce()`
  (16 OS-CSPRNG bytes, URL-safe base64, 22 chars; panics with no fallback if no OS CSPRNG is
  available). Raw pass-through remains available through the generic `headers` handler.
- Rationale: a typo or malformed source in a raw CSP value silently weakens or disables the policy
  in the browser; load-time validation gives a located error instead, and the structured builder
  makes per-response nonces and deterministic output possible. The generic `headers` handler keeps
  byte-exact upstream compatibility for users who want it.
- Status: accepted (caddy-rs extension)
- Tracking: T-COMPAT-003
- Test: `crates/http/src/csp.rs` `all_standard_directives_parse_and_serialize`,
  `nonce_generation_and_placeholder_expansion`,
  `strict_dynamic_and_unsafe_hashes_are_supported`, `report_uri_and_report_to_are_supported`,
  `invalid_directives_are_rejected_with_located_errors`,
  `builder_produces_a_valid_deterministic_header_value`,
  `header_round_trip_normalizes_whitespace_and_tolerates_trailing_semicolon`

## DIV-0121 — `security_headers` adds HSTS preload validation and HTTPS-only emission

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no HSTS-specific handler. The generic `headers` handler
  (`modules/caddyhttp/headers/headers.go`) stages the `Strict-Transport-Security` value the user
  spells out, on every response the route matches, with no validation of `max-age`,
  `includeSubDomains` or `preload`, no preload-list admission checks or warnings, and no
  transport-aware gating.
- caddy-rs behaviour: `security_headers` accepts a structured
  `HstsConfig { max_age, include_subdomains, preload }`. The request-scoped staging path used by
  the `Handler` emits `Strict-Transport-Security` only when `Request::tls` is true; plain-HTTP
  responses get no HSTS header even when configured. `SecurityHeaders::apply(&mut HeaderMap)` and
  the shared `stage_headers` helper remain the unconditional form for route-engine callers that own
  the HTTPS condition. The value follows RFC 6797
  (`max-age=<seconds>[; includeSubDomains][; preload]`). `validate()` hard-rejects `max_age == 0`,
  `max_age < HSTS_MIN_MAX_AGE` (15552000), `preload` without `include_subdomains`, and invalid
  header values. `SecurityHeadersConfig::warnings()` reports - without failing - a preload
  `max_age` below `HSTS_PRELOAD_MIN_MAX_AGE` (31536000), naming the required minimum and the
  configured value, and the fact that preload-list membership cannot be verified or looked up at
  config time.
- Rationale: the preload directive is a long-lived commitment that browsers and the preload list
  validate, and emitting HSTS over cleartext is a defect; the measurable requirements are enforced,
  and the unverifiable online requirement is surfaced as a warning so offline configuration still
  works.
- Status: accepted (caddy-rs extension)
- Tracking: T-COMPAT-003
- Test: `crates/http/src/security_headers.rs` `hsts_is_staged_on_https_responses_only`,
  `hsts_header_value_matches_rfc_6797`,
  `preload_below_one_year_warns_with_required_and_configured_max_age`,
  `preload_membership_cannot_be_verified_at_config_time`, `hsts_directives_are_configurable`

## DIV-0122 — `security_headers` is a caddy-rs extension whose staged headers follow route-order precedence

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no `security_headers` handler. Its generic `headers` handler
  writes response headers into the shared response writer at request time, so a handler that runs
  later (including inside a `subroute`) overwrites an earlier value; an unmatched request ends as
  an empty 200.
- caddy-rs behaviour: `security_headers` configures secure defaults (`X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`) plus
  opt-in CSP/HSTS/Permissions-Policy per handler object. Values are staged into the request's
  pending response headers, expanded with ReplaceKnown at request time, and merged onto the
  response by the router. Within one chain the last staging handler wins; a continuing `subroute`
  shares the staged map and wins over its parent; a `subroute` that responds is merged at its own
  level before the outer merged map, so the outer value wins there (documented and code-verified;
  the conflicting-values test covers the continuing-subroute shape, the responding shape is a
  residual). A staged value replaces a same-named response header instead of appending like
  Caddy's `Add`. Error responses produced before the handler runs are not decorated;
  `security_headers` in `handle_errors` is the explicit opt-in. Unmatched requests end as the
  caddy-rs 404 (DIV-0068), not Caddy's empty 200.
- Rationale: the handler is an advertised caddy-rs extension, not a Caddy module; staging through
  T-ROUTE-011 keeps it consistent with the generic `headers` handler and lets the route engine
  compose per-route, per-subroute and global configurations without a second header pipeline.
- Status: accepted (caddy-rs extension)
- Caddyfile surface: `header { security_headers { ... } }` is the Caddyfile form of the same
  extension (T-ROUTE-051). It nests inside the standard `header` block and adapts to the same
  `headers` handler JSON with a `security_headers` object, so Caddyfile and hand-written JSON
  configurations produce identical documents. Stock Caddy v2.11.9 does not understand the
  block: its generic `header` parser treats `security_headers` and the block's lines as
  header operations, so `caddy adapt` succeeds with bogus headers and `caddy validate`
  accepts the result (oracle-checked against the pinned v2.11.9). A Caddyfile using the
  block is therefore not portable back to Caddy, and caddy-rs is deliberately strict where
  Caddy is silently wrong.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/router.rs` `security_headers_apply_to_any_handler_response`,
  `per_route_security_headers_override_global_defaults`,
  `subroute_security_headers_inherit_and_override_parent`,
  `security_headers_expand_placeholders_in_values`,
  `internal_error_responses_are_not_decorated_unless_configured`; Caddyfile surface:
  `crates/config/tests/security_headers_adapt.rs` and the local `security_headers` fixture
  (`crates/config/tests/fixtures/local/security_headers.caddyfile`/`.json`)

## DIV-0123 — `file_server` rejects symbolic links instead of serving through them

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 `file_server` opens the matched path with `os.Open` and follows
  symbolic links wherever the OS resolves them, so a symlink inside the site root (file or
  directory, including `index.html` candidates and sidecar/ETag files) is served from its target
  even when the target is outside the root. There is no symlink-containment check.
- caddy-rs behaviour: `FileServerHandler` checks every path component from the resolved file up to
  the site root with `symlink_metadata`; if any component is a symbolic link the request is answered
  `403 Forbidden`, including directory index candidates, ETag sidecars and precompressed variants.
  Regular files and real subdirectories are unaffected.
- Rationale: a symlink is the classic way to escape a site root and read arbitrary files; refusing
  symlinks is deliberate hardening. Deployments that intentionally serve symlinked content must
  point `root` at the real directory (or bind-mount it) instead.
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/http/src/file_server.rs` `symlink_to_outside_root_is_rejected`,
  `symlink_to_hidden_file_is_rejected`, `symlink_directory_to_outside_is_rejected`

## DIV-0124 — Caddyfile imports accept explicit absolute paths; default mode validates what a relative import may read

- Area: Config
- Caddy behaviour: Caddy v2.11.9 resolves a file/glob import in `parse.go`: an absolute pattern is
  used as-is (`filepath.IsAbs` keeps the glob pattern) and a relative one is joined to the importing
  Caddyfile's directory; `..` components are resolved by `filepath.Join`/`Glob` with no containment
  check, so a Caddyfile can import any readable file on the host. Symbolic links are followed with no
  target validation, and permissions and size are not inspected. A pattern that matches nothing
  fails with `File to import not found: <pattern>`.
- caddy-rs behaviour: the policy is selected by the `stock_compat` global option (DIV-0130), detected
  from the global-options block before any import is expanded.
  - Default (`stock_compat` absent/false): an explicit absolute file or glob pattern is accepted and
    resolved as written, matching Caddy and the reported deployment
    (`import /etc/caddy/host_*.conf`). A relative pattern is resolved against the importing file's
    directory and must stay inside it both lexically
    (`Import path escapes the Caddyfile directory: <pattern>`) and after symbolic links are resolved
    (`Import path escapes the Caddyfile directory through a symbolic link: <file>`). Every resolved
    file must be a regular file no larger than 8 MiB, must not be writable by group or other, and
    (on Unix) must be owned by root or by the owner of the importing Caddyfile; violations are
    located `InvalidConfig` errors (`Could not import <pattern>: ...`). A symbolic link is followed
    and its target is what is validated, so an in-tree symlink to an in-tree file is allowed and a
    symlink out of the tree is rejected.
  - `stock_compat true`: resolution and validation mirror Caddy v2.11.9 exactly: absolute patterns
    as-is, relative joined to the importing directory, no containment, no symlink-target or
    permission checks and no size cap.
  In both policies nested imports resolve relative to the file that contains them, the
  one-wildcard glob rule and the dotfile skip are unchanged, and failures are located diagnostics.
  Default-mode diagnostics name the pattern as the user wrote it (no absolute Caddyfile directory
  leak); an explicit absolute pattern is of course reported as written.
- Rationale: an absolute import path is legitimate operator configuration — rejecting it forced
  symlinks or copies and broke the documented `/etc/caddy` layout. The default keeps the security
  property that a relative import cannot read outside the configuration root and that an import
  cannot be a file another account can rewrite; `stock_compat true` restores byte-for-byte stock
  behaviour for deployments that require it.
- Residual: validation and read are not one atomic operation (an owner who can rewrite the import
  directory between them can change the file); the import directory must therefore be trusted and
  owned by root or the importing file's owner, which the default-mode permission rule enforces for
  the file itself. When adapting stdin there is no importing file, so the owner anchor is unknown;
  the strict default then applies and the import file must be owned by root. Both are accepted
  because the threat model is a non-owner injecting configuration, not an owner attacking
  themselves.
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/imports_files.rs` (`absolute_file_import_is_allowed`,
  `absolute_glob_import_is_allowed`, `absolute_directory_import_is_rejected`,
  `absolute_import_writable_by_others_is_rejected`,
  `relative_import_through_escaping_symlink_is_rejected`,
  `relative_import_through_in_tree_symlink_is_allowed`, `parent_traversal_import_is_rejected`,
  `traversal_through_child_directory_is_rejected`, `file_import_without_a_source_path_fails_loudly`,
  `stock_compat_true_allows_parent_directory_imports_like_caddy`,
  `stock_compat_false_keeps_the_strict_import_policy`,
  `nested_file_imports_resolve_relative_to_each_file`,
  `cross_file_import_cycles_are_rejected`); `crates/config/tests/import_named_routes.rs`
  (`missing_absolute_file_import_fails_loudly_with_a_located_error`). The adapter-conformance
  harness materialises fixture directories instead of symlinking them
  (`tools/compat/adapt_conformance.py`): a symlinked `testdata/` is a canonical escape under the
  default policy, and copying reproduces Caddy's own fixture layout.

## DIV-0125 — `server_identity` is a caddy-rs extension that defaults to claiming caddy-rs, with opt-in Caddy-compatible strings

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no server-identity option. It unconditionally sends
  `Server: Caddy` on every HTTP response and `SERVER_SOFTWARE: Caddy/2.11.9` to FastCGI upstreams;
  the value is set before routing, so the synthetic errors Caddy generates itself carry it too and
  a handler may override it.
- caddy-rs behaviour: the Caddyfile global `servers { ... }` block accepts bare `server_identity`
  (the default mode), `server_identity default|name-only|compatible|none` and
  `server_identity custom <string>`. A block form, an unknown mode, extra arguments and an empty
  `custom` value are located adaptation errors. The JSON field
  `apps.http.servers.<name>.server_identity` must be a string; empty/blank, `null` and non-string
  values are located errors at that exact path, and the same check runs in config validation so
  `validate`/`load` fail rather than only apply. Rendering: `default` = `caddy-rs/<build version>`
  on both the HTTP `Server` header and FastCGI `SERVER_SOFTWARE`; `compatible` = `Caddy` on HTTP
  and `Caddy/2.11.9` on FastCGI (the exact strings Caddy v2.11.9 emits); `name-only` = `Caddy` on
  both with no version; `custom <string>` = the operator string verbatim on both; `none` = both
  omitted. The value domain and the pre-routing coverage of the stamp are DIV-0126.
- Rationale: caddy-rs must not silently claim to be Caddy, so the default identifies the real
  implementation (`caddy-rs/<version>`); `compatible` is an explicit opt-in for deployments that
  need byte-identical Caddy strings (dashboards, WAFs, upstream health checks), and `none` covers
  deployments that omit the surfaces entirely.
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/server_identity.rs` (Caddyfile forms and located errors),
  `crates/server/tests/http_server_identity.rs` (HTTP `Server` header per mode),
  `crates/config/tests/fixtures/local/servers_addr_specific.json` (JSON field accepted) and the
  unit tests in `crates/core/src/identity.rs`

## DIV-0126 — `server_identity` custom values must be visible ASCII and the header is stamped before routing

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 has no identity option. It writes `Server: Caddy` into the
  response header before routing (`modules/caddyhttp/server.go:631`), so its own synthetic
  responses (the `413` body-limit rejection, pre-routing redirects, `5xx`) carry the value, a
  handler may still override it, and a header value Go's writer considers invalid fails the write
  instead of silently omitting the header.
- caddy-rs behaviour: the five modes themselves are DIV-0125. The configured identity is now
  applied to the responses the router never produces: the pre-routing `413` body-limit rejection,
  the automatic-HTTPS pre-router responses (the HTTP-01 challenge answers `200`/`404` and the
  HTTP→HTTPS `308` redirect), HTTP/2 extended-CONNECT `501`s, the upgrade-without-connection
  `502`, and the handler-error responses all carry the configured `Server` value, while `none`
  still omits it. The derived cleartext challenge/redirect listener has no server config of its
  own, so it inherits the `server_identity` of the HTTPS site it was derived from. Status codes, bodies and every other header are
  unchanged, and an explicit `Server` header set by a handler is preserved because the stamp is
  skipped when the header already exists. A `custom` identity whose value cannot be an HTTP header
  value is a located configuration error instead of a silently omitted header: only U+0020..=U+007E
  (space through `~`) is accepted, so control characters, tabs, DEL and non-ASCII (U+0080 and above)
  fail `adapt`, `validate` and `load` with `... value cannot be used as an HTTP `Server` header
  value: character U+XXXX at byte N is not visible ASCII; use only characters in U+0020..=U+007E`.
  The JSON error stays located at `apps.http.servers.<name>.server_identity`; the Caddyfile error
  is located at the directive line and names the directive. Non-ASCII is rejected rather than
  percent-encoded because the identity is an opaque operator string: re-encoding it would emit a
  value the operator did not configure, and the surfaces this build writes (hyper `HeaderValue`)
  carry only visible ASCII. The response writer keeps a defensive skip for a value hyper cannot
  store, but no configuration can reach it.
- Rationale: an identity only helps if it appears on every response the server sends, including the
  ones a struggling deployment shows most often (`413`/`5xx`); leaving those unlabelled made
  caddy-rs look like a different product on exactly those paths. Refusing an unusable custom value
  at load turns a silent, hard-to-notice mismatch into an actionable error.
- Status: accepted
- Tracking: T-COMPAT-003
  (U+0020..=U+007E) domain were implemented by the SEC-FU-IDENTITY-COVERAGE change
  (`reviews/SEC-FU-IDENTITY-COVERAGE.json`, approved at `ad1c18bf594e`); no plan task carries those
  two obligations in its acceptance, so this divergence and the tests below are their record.
- Test: `crates/core/src/identity.rs` (visible-ASCII domain and located error),
  `crates/config/tests/server_identity.rs` (Caddyfile custom value rejected at the directive line),
  `crates/server/tests/http_server_identity.rs` (pre-routing `413` carries the configured header,
  `none` stays silent, a valid custom value is emitted verbatim on routed responses),
  `crates/server/tests/http_auto_https.rs` (`derived_http_listener_carries_the_configured_identity`
  proves the redirect and the HTTP-01 challenge answer carry the site's identity,
  `derived_http_listener_none_mode_emits_no_identity` proves `none` stays silent on both)

## DIV-0130 — `stock_compat` is a caddy-rs configuration extension

- Area: Config
- Caddy behaviour: Caddy v2.11.9 has no `stock_compat` option. The Caddyfile global-options parser
  rejects the token with `unrecognized global option: stock_compat`
  (`external/caddy/caddyconfig/httpcaddyfile/httptype.go:399`), while Caddy's JSON `Config` struct
  has no such field, so `encoding/json` silently ignores an unknown top-level `"stock_compat"` key
  and the configuration loads with stock behaviour.
- caddy-rs behaviour: the configuration surface is implemented (SEC-ABS-IMPORT, ahead of T-CONF-070,
  ADR-0010, STOCK-COMPAT.md). A top-level JSON boolean `stock_compat` (absent = `false`; a string,
  number or `null` is a located error at `stock_compat`) and the Caddyfile global option
  `stock_compat` (bare = `true`) or `stock_compat true|false` are accepted; a non-empty block, an
  extra argument, an unknown token or a second `stock_compat` option is a located adaptation error
  at the directive line. An empty block (`stock_compat {}`) is indistinguishable from the bare form
  in the directive model and is treated as bare `true`. Policy selection is whole-block and
  order-insensitive: `stock_compat true` anywhere at depth 1 of the global-options block applies to
  every import in the file, including one written before it, so the switch is not a forward-only
  toggle. The value is one per configuration and is carried into the runtime
  generation; there is no per-server or per-route override in v1. The adapter emits a top-level
  `stock_compat: true` key only when the switch is enabled, so a configuration that does not use it
  adapts exactly as before. Every apply emits one INFO `tracing` event naming the effective mode as a
  structured `stock_compat = <bool>` field (with a human-readable consequence), before the listeners
  start and once per generation rather than per request, so the choice is visible in the startup log
  and on reload (ADR-0010 section 5). The switch gates the file/glob import path policy
  (DIV-0124), the reverse-proxy response-hardening profile (DIV-0131) and identity resolution
  (DIV-0132), and it selects verbatim access logging instead of the built-in query-parameter
  redaction default (DIV-0133/DIV-0134). A stock Caddy loading the same
  Caddyfile fails adaptation, and a stock Caddy loading the same JSON ignores the key, so the same
  file behaves differently on the two implementations — that is the divergence this entry registers,
  and STOCK-COMPAT.md states it for operators.
- Rationale: the switch is what makes every secure-by-default divergence reversible per
  configuration (ADR-0010). It is additive — no Caddy field changes meaning — and it is explicit in
  the table, so it cannot be mistaken for a Caddy option.
- Status: accepted (implemented: configuration surface, import-path policy, response hardening and
  its inertness under `stock_compat true`, identity resolution, and the access-log query-parameter
  redaction default — see [STOCK-COMPAT.md](STOCK-COMPAT.md) for the row-by-row tests)
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/imports_files.rs`
  (`stock_compat_option_parses_all_documented_forms`,
  `malformed_stock_compat_option_fails_with_a_located_error`,
  `stock_compat_round_trips_through_the_typed_config`, `stock_compat_must_be_a_boolean_in_json`,
  `stock_compat_true_allows_parent_directory_imports_like_caddy`,
  `stock_compat_false_keeps_the_strict_import_policy`), and
  `crates/server/tests/http_stock_compat.rs` (the response-hardening rows and their inertness under
  `stock_compat true`).

## DIV-0131 — Reverse-proxy responses get secure-by-default headers and lose fingerprint headers

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 adds no security response headers. It writes `Server: Caddy`
  before routing, appends `Via: <proto> Caddy` to proxied responses, and otherwise forwards the
  upstream header set unchanged, including `Server` and `X-Powered-By`. `Strict-Transport-Security`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` appear
  only when the operator or the upstream sets them.
- caddy-rs behaviour: implemented by T-HTTP-160/T-PROXY-060 (ADR-0010, STOCK-COMPAT.md). With
  `stock_compat` absent or `false`, every response produced by a `reverse_proxy` handler (buffered,
  streaming and `handle_response`-synthetic paths) gets
  `Strict-Transport-Security: max-age=31536000` on TLS requests only, plus
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin` and
  `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()`;
  an upstream `Server` and `X-Powered-By` are removed. The profile is set-if-absent: an
  upstream-provided value for one of the five headers wins, and an explicit `header` or
  `security_headers` value (merged onto the response after the handler returns) wins. An explicit
  `security_headers` handler in the same route chain as the `reverse_proxy` opts that route out of
  the implicit profile entirely. `stock_compat true` makes the profile inert. Not applied to
  non-proxy responses, `forward_auth` subrequests, HTTP `101` responses (which still lose the
  fingerprint headers) or the proxy error path's `502`/`504` (the DIV-0122 residual).
  `Content-Security-Policy` is never defaulted, and `Via: <proto> Caddy` is unchanged.
- Rationale: the program's primary workload is a reverse proxy in front of applications whose
  operators rarely write a header policy; the five defaults close named browser-security gaps
  (downgrade, MIME confusion, clickjacking, referrer leakage, feature abuse) and removing the two
  fingerprint headers raises the cost of version-targeted exploitation. The divergence is
  reversible per configuration and every precedence rule is documented, so an application that
  needs a different policy can set it explicitly.
- Status: accepted (caddy-rs extension)
- Tracking: T-COMPAT-003
- Test: `crates/http/src/security_profile.rs` (constants, TLS gating, set-if-absent,
  fingerprint stripping), `crates/proxy/src/handler.rs` (buffered and streaming paths,
  `handle_response` synthetics, `header_down` precedence) and
  `crates/server/tests/http_stock_compat.rs` (end-to-end matrix); the oracle runtime probe
  `proxy-forwarded#root` proves the profile is live at implementation commit 71ddde7.

## DIV-0132 — The default `Server` identity depends on `stock_compat` and reverse-proxy use

- Area: HTTP
- Caddy behaviour: Caddy v2.11.9 always sends `Server: Caddy` on HTTP responses and
  `SERVER_SOFTWARE: Caddy/2.11.9` to FastCGI upstreams; it has no identity option.
- caddy-rs behaviour: implemented (T-CONF-071, ADR-0010 section 3). An explicit `server_identity`
  wins in every mode. When it is absent: `stock_compat true` resolves to `compatible` (`Caddy` on
  HTTP, `Caddy/2.11.9` on FastCGI); `stock_compat false` with a configuration that contains a
  `reverse_proxy` handler suppresses the HTTP `Server` header entirely while leaving FastCGI
  `SERVER_SOFTWARE` at `caddy-rs/<version>`; `stock_compat false` without any `reverse_proxy`
  handler keeps `caddy-rs/<version>` on both surfaces. Reverse-proxy use is detected once per
  generation by walking `handle`, `subroute`, `handle_errors` and named-route trees, so the
  suppression is config-wide rather than per-response. This refines the absent-field default of
  DIV-0125; an explicit `server_identity default` re-enables `caddy-rs/<version>`, and an explicit
  `none`/`custom`/`name-only`/`compatible` keeps its documented meaning.
- Rationale: `stock_compat true` must restore the stock identity or it does not mean "behave like
  stock Caddy", while the secure default must not advertise the implementation on the
  browser-facing surface of a reverse proxy. FastCGI is left alone because it is upstream-visible,
  not a browser fingerprint, and applications may key on it. The config-wide scope is a documented
  consequence of the response type having no extension map.
- Status: accepted (implemented: absent `server_identity` resolves through `stock_compat`, and the
  FastCGI `SERVER_SOFTWARE` value follows the resolved identity)
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_server_identity.rs` (8 tests: the four-row matrix and explicit
  modes), `crates/core/src/identity.rs` (resolution rules), `crates/server/tests/http_stock_compat.rs`
  (`stock_compat_true_resolves_the_stock_caddy_identity`)
  and `crates/server/tests/http_fastcgi_tls.rs`.

## DIV-0133 — `redaction.query_parameters` is a caddy-rs log-encoder extension

- Area: Logging
- Caddy behaviour: Caddy v2.11.9's `json`/`console` log encoders accept only their documented
  options; an unknown encoder key is rejected when the configuration is decoded. Caddy has no
  `redaction` encoder option. Query-parameter redaction exists only as the explicit
  `caddy.logging.encoders.filter.query` filter module (`modules/logging/filters.go:316-360`),
  configured through a `filter` encoder's `fields`/`request>uri` rules.
- caddy-rs behaviour: implemented by T-ADMIN-050 (ADR-0012). `logging.logs.<name>.encoder.redaction`
  is accepted on the `json` and `console` encoders (including a `filter` encoder's `wrap` object)
  with exactly one key, `query_parameters`: an optional array of parameter names. Absent = the
  built-in default list; `[]` = no query-parameter redaction for that sink; a non-empty array
  replaces the default list exactly. A non-array value, non-string/empty/duplicate entries, an
  unknown key under `redaction`, and the field on an unsupported encoder are located errors.
  `stock_compat` does not change acceptance (ADR-0010): the extension is explicit configuration and
  applies in both modes.
- Rationale: the built-in default (DIV-0134) needs an inspectable, per-sink override and a working
  opt-out for debugging. Reusing the existing internal `RedactionPolicy::query_parameters` primitive
  keeps the surface small; a caddy-rs-only option is registered rather than hidden so a
  configuration using it is not silently ported to stock Caddy.
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/logging_config.rs` unit tests (absent/`[]`/replacement list, located
  errors for invalid shapes, filter-`wrap` acceptance, stock-mode acceptance) and
  `crates/server/tests/http_observability.rs` end-to-end
  (`explicit_empty_redaction_query_parameters_logs_the_query_verbatim`,
  `explicit_redaction_query_parameters_replace_the_builtin_default`,
  `filter_encoder_wrap_redacts_before_applying_filters`); the field is accepted in both
  `stock_compat` modes.

## DIV-0134 — Access logs redact sensitive query parameters by default

- Area: Logging
- Caddy behaviour: Caddy v2.11.9 logs the request target verbatim: the access entry's
  `request.uri` is `r.RequestURI` (path and query) with no default redaction
  (`modules/caddyhttp/marshalers.go:50`). Only credential headers are redacted by default
  (`internal/logmarshalers.go:13-34`); query parameters are redacted only when the operator
  configures the explicit `caddy.logging.encoders.filter.query` filter.
- caddy-rs behaviour: implemented by T-ADMIN-050 (ADR-0012). With `stock_compat false` (default), every
  access entry's `request.uri` has the values of the built-in list (`access_token`, `api_key`,
  `apikey`, `client_secret`, `id_token`, `password`, `refresh_token`, `secret`, `session_id`,
  `token`) replaced with `"REDACTED"`, preserving path, names, order and other parameters; matching
  is exact and case-sensitive; empty values and bare `name` pairs follow the documented rule; the
  redaction happens on the entry model before encoding, so it applies to `json`, `console` and
  `filter`-wrapped encoders and before explicit filter actions. `stock_compat true` logs the query
  verbatim (stock), while an explicit `redaction.query_parameters` list still applies. Credential
  headers keep the stock default redaction; the `should_log_credentials` residual (`T-ADMIN-047`) is
  unchanged. Scope is the access entry only: error/debug log lines, custom `log_append` fields and
  upstream logs are not rewritten, and percent-encoded names/`;` separators are not matched.
- Rationale: access logs are copied to shippers, retention stores and support bundles, and query
  strings routinely carry bearer credentials. The default is a small, exact, documented list rather
  than a heuristic; it is reversible per sink (`[]`) and globally (`stock_compat true`), and it does
  not change request or response behaviour. Redaction protects the log only: secrets in URLs still
  leak via `Referer`, browser history and upstream servers, which the docs state explicitly.
- Status: accepted
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/access_log.rs` unit tests (`builtin_sensitive_query_parameter_list_is_pinned`,
  `default_redaction_redacts_every_builtin_query_parameter` — each built-in name, non-listed name,
  empty value, bare pair, case sensitivity) and `crates/server/tests/http_observability.rs`
  end-to-end (`access_log_redacts_builtin_query_parameters_by_default`,
  `explicit_empty_redaction_query_parameters_logs_the_query_verbatim`,
  `stock_compat_true_logs_the_query_verbatim`, `explicit_redaction_query_parameters_replace_the_builtin_default`,
  `filter_encoder_wrap_redacts_before_applying_filters`, `console_encoder_renders_the_redacted_query`);
  oracle evidence in `docs/compatibility/TESTING.md` §"Access-log query redaction oracle evidence
  (DIV-0133/DIV-0134)" shows stock Caddy v2.11.9 logging the full query, caddy-rs `REDACTED`, and
  caddy-rs under `stock_compat true` verbatim for the same request.

## DIV-0135 — A simplified named route keeps all handlers (upstream security fix ahead of the pin)
- Status: accepted
- Area: Caddyfile adapter
- Caddy behaviour: Caddy v2.11.9's `extractNamedRoutes` simplified a named route whose body adapted
  to exactly one matcher-less route by appending only that route's **first** handler
  (`route.HandlersRaw = append(route.HandlersRaw, subroute.Routes[0].HandlersRaw[0])`,
  `caddyconfig/httpcaddyfile/httptype.go:534-536`). Every handler after the first was dropped from
  the server's `named_routes` entry, so `&(protected) { header X-Test retained; basic_auth {...} }`
  adapted without the `authentication` handler and an `invoke` of the route ran unauthenticated.
- caddy-rs behaviour: the whole route is kept (`route = subroute.Routes[0]`, upstream Caddy
  ec849f542c43), preserving every handler and its order; the `else` branch still emits the subroute
  form for any other shape. Adapted JSON for such a named route therefore differs from v2.11.9 for
  the same Caddyfile: the multi-handler route is no longer truncated, and
  `crates/config/tests/fixtures/upstream/invoke_nested_named_routes.caddyfiletest` pins the fixed
  output instead of the pinned corpus's truncated one, and the generated
  `docs/compatibility/ADAPT-CONFORMANCE.md` consequently classifies the pinned
  `invoke_nested_named_routes.caddyfiletest` as the single triaged mismatch (138/264 exact matches)
  until the pin includes ec849f542c43. No accepted configuration or other emitted JSON changes;
  single-handler and matcher-bearing named routes adapt exactly as before.
- Rationale: keeping the v2.11.9 output would preserve a security bug — silently dropping an
  authentication (or any later) handler from an invoked named route is exactly the class of failure
  the compatibility contract must not reproduce, and it fails silently rather than loudly. The fix
  is upstream's own, is behaviour-preserving for every configuration that was not being truncated,
  and will match the pinned baseline as soon as the pin includes ec849f542c43.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/named_route_handlers.rs` (whole-route JSON, handler order, subroute
  control case, single-handler case), `crates/http/tests/named_route_handlers.rs` (adapted handlers
  served through the real router: authorised 200 with `X-Test`, unauthenticated 401 with `X-Test`),
  and the updated golden fixture above via `crates/config/tests/upstream_adapt.rs`.

## DIV-0136 — `file_server` refuses a regular file addressed with a trailing separator (upstream security fix ahead of the pin)
- Status: accepted
- Area: HTTP handlers (static files)
- Caddy behaviour: Caddy v2.11.9 `file_server` trimmed a trailing `/` from the sanitized filename
  before stat and, with `canonical_uris` disabled, served the regular file for `/secret.env/`
  (`modules/caddyhttp/fileserver/staticfiles.go:301-303`). `path` matchers evaluate the untrimmed
  request path, so a rule such as `path *.env` did not match `/secret.env/` and the file server
  served the file the matcher meant to block; on Windows the `/`-only trim left the `\` that
  `SanitizedPathJoin` had appended, so stat failed and `/file/` answered 400 instead of the
  canonical redirect or a 404.
- caddy-rs behaviour: mirrors upstream 5bd0b9355d44. The target path is the cleaned decoded request
  path (`path.Clean`, dropping `.` segments and repeated slashes; `..` is already 403) with the
  trailing OS separator trimmed from the relative part only, so a filesystem root keeps its
  separator (`root.join("")` is the root, never an empty path or `C:`). After implicit-index
  resolution and the canonical redirect, a request whose decoded path still ends with a separator —
  including `%2F`, `%5c`/`%5C`, repeated `//` and `/./` — takes the file server's not-found outcome
  (404, or pass-through to the next handler with `pass_thru`) instead of serving the file.
  `canonical_uris=true` keeps its 308 to `/secret.env`; directories keep serving their implicit
  index (`/dir/`, `/dir`) and `/dir/index.html/` is 404. Precompressed sidecars cannot resurrect
  the file. No accepted configuration or emitted JSON changes.
- Rationale: keeping the v2.11.9 output would serve a file that `path` matchers deliberately do not
  match — a matcher/access-control bypass — and would answer 400 on Windows for the same request.
  The stricter 404 is upstream's own decision (PR #8379) and matches the pinned baseline as soon as
  the pin includes 5bd0b9355d44. The pinned v2.11.9 oracle precedes the fix, so oracle replay
  cannot prove the rejection and the proof stays in unit tests. The `caddy-rs-http` crate has no
  debug-log facility, so upstream's debug line is not reproduced; the rejection is observable as
  the 404/pass-through response.
- Tracking: T-COMPAT-003
- Test: `crates/http/src/file_server.rs`
  `a_regular_file_addressed_with_a_trailing_separator_is_not_served` (six trailing-separator
  spellings, plus the plain path still serving),
  `a_precompressed_sidecar_does_not_resurrect_a_trailing_separator`,
  `a_trailing_separator_on_a_file_passes_through_to_the_next_handler`,
  `canonical_redirect_for_a_trailing_separator_on_a_file_is_kept`,
  `directories_keep_the_implicit_index_and_reject_an_index_file_as_a_directory` and
  `a_filesystem_root_keeps_its_separator_and_still_browses`.

## DIV-0137 — Comma-combined values in a single allowlisted header field are accepted (RR1 policy)
- Status: accepted
- Area: HTTP security headers (CGI/FastCGI header-alias sanitisation, `SEC-FU-HDR-RR1`)
- Caddy behaviour: the v2.11.9 alias-sanitisation loop (`modules/caddyhttp/server.go` L844-L909)
  removes an allowlisted header only when it arrives as **repeated field lines**; a single field
  line whose value contains commas is kept, and FastCGI env construction joins repeated field values
  with `", "` (`modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go` `buildEnv`). So `Remote_user: a, admin` on
  one line reaches PHP as `HTTP_REMOTE_USER="a, admin"`; comma-combining is legal list syntax, not
  an injection signal by itself.
- caddy-rs behaviour: the policy decided for `T-HTTP-162` matches the oracle. Comma-combined values
  in a single field line are accepted and forwarded verbatim for allowlisted names; there is no
  value-level comma rejection at config load or request time. The sanitisation rule R6 (from
  `T-HTTP-155`, `docs/security/REVIEW-header-alias-allowlist.md`) drops **repeated field lines**
  whole and never a single comma-containing value, so the allowlist stays the trust boundary rather
  than a value filter. On trunk before the filter lands, the FastCGI env builder already forwards
  the single line unchanged; the pinned test below fixes that baseline.
- Rationale: rejecting comma-containing values would depart from Caddy v2.11.9 and break
  legitimate list-valued headers (`X-Forwarded-For`, `Accept`, ...). R6's repeated-field drop is
  the control against value injection; it is a field-line rule, not a value rule, and must not be
  silently widened to claim comma values are dropped.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/fastcgi.rs`
  `fastcgi_single_comma_combined_remote_user_reaches_cgi` (one `Remote_user: a, admin` field line
  reaches the CGI env as `HTTP_REMOTE_USER="a, admin"`).

## DIV-0138 — Mixed-separator allowlist entries are refused at config load (RR3 policy)
- Status: accepted
- Area: HTTP server configuration (CGI/FastCGI header-alias allowlist, `SEC-FU-HDR-RR3`)
- Caddy behaviour: v2.11.9's alias-sanitisation loop special-cases a client header name that contains
  **both** `_` and `.` (`modules/caddyhttp/server.go` L844-L870): the name is kept when *either*
  allowlist holds a literal exact entry for that spelling (`underscoreExactAllow[k]` or
  `dotExactAllow[k]`), and dropped otherwise. An entry such as `webhook_user.id` is therefore legal
  configuration in `expected_underscore_headers` or `expected_dot_headers`, and it allowlists the
  mixed header.
- caddy-rs behaviour: an allowlist entry containing the other separator is refused at config load
  with a located error naming the field, index and offending value (R4 in
  `docs/security/REVIEW-header-alias-allowlist.md`; implemented by `parse_header_allowlist` in
  `crates/server/src/limits.rs`, branch `agent/http-155`). A mixed spelling can therefore never be
  allowlisted, and once the filter lands a client name containing both separators is always
  dropped. The refusal is deliberate: a backend that folds `-`, `_` and `.` onto one CGI/FastCGI
  variable cannot distinguish `Webhook-User`, `Webhook_User`, `Webhook.User` and
  `Webhook_user.id`, so the spelling is rejected instead of trusting the operator to notice the
  fold. This departs from v2.11.9, which accepts the entry.
- Rationale: the allowlist is a trust boundary for backends that fold separators; a mixed spelling
  widens that boundary across *both* lists at once and is exactly the confusion class the review
  flagged (RR3). Fail-closed at load is a loud, testable outcome ("unsupported is a valid,
  advertised outcome"), while silently honouring the mixed entry reproduces the oracle's footgun.
- Tracking: T-COMPAT-003
  integration is still pending and unmerged on trunk; RR1/RR4 are T-HTTP-162/T-HTTP-165)
- Test: `crates/server/src/limits.rs` `tests::rejects_header_allowlist_invalid` on branch
  `agent/http-155` asserts the mixed entry `Remote.User` under `expected_underscore_headers` is
  refused with an error naming the other separator. The test and the enforcement land together with
  T-HTTP-155; there is no trunk enforcement to test before that merge.

## DIV-0139 — `admin.identity` is PEM certificate/key material, not certmagic/ACME issuance
- Status: accepted
- Area: Admin / TLS
- Caddy behaviour: Caddy v2.11.9's `caddy.IdentityConfig` (`external/caddy/admin.go:159-176`) holds
  `identifiers` (names or IP addresses that refer to the server, for which identity certificates
  are obtained) and `issuers` (`tls.issuance` modules, defaulting to ACME issuers for ZeroSSL and
  Let's Encrypt), plus internal certmagic state. `Context.IdentityCredentials`
  (`external/caddy/admin.go:660-675`) resolves the endpoint's credentials through certmagic's
  client-credentials path, which obtains, caches and renews a certificate for the identifiers.
  There is no field that supplies the identity certificate and key directly.
- caddy-rs behaviour: `AdminIdentity` (`crates/core/src/config.rs`) carries two caddy-rs extension
  fields, `certificate` (a PEM certificate chain) and `key` (a PEM private key: PKCS#8
  `PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`), which must be supplied together.
  `validate_admin_identity` (`crates/core/src/validate.rs`) rejects one without the other with a
  located error at the missing field, then reads each path and requires at least one PEM block of
  the expected kind, so an unreadable file or a missing `CERTIFICATE`/`PRIVATE KEY` block is a
  located `admin.identity.certificate`/`admin.identity.key` error. The cryptographic load (chain and
  key pairing, key type, TLS usability) happens when the remote listener is built
  (`remote_admin_tls_config`, `crates/server/src/listeners.rs`, via `TlsCertificate::from_pem`,
  with located `admin.identity` errors). There is no admin-endpoint certmagic/ACME issuance,
  certificate cache or renewal, so a non-empty `issuers` array is a located
  `admin.identity.issuers` error telling the operator to use the PEM fields. Stock Caddy v2.11.9
  decodes a JSON configuration carrying the extension `certificate`/`key` keys without complaint
  (Go ignores unknown fields) and then resolves its identity through certmagic; caddy-rs uses the
  PEM pair and rejects the upstream issuance fields instead of ignoring them.
- Rationale: the admin endpoint is a control surface, normally bound to loopback, with no public
  hostname whose ownership can be validated; wiring certmagic issuance for it would add ACME
  accounts, challenge listeners and renewal scheduling for a listener that must be deterministic at
  startup. A PEM pair reuses the already-tested TLS stack and makes the missing-issuance difference
  a loud, located rejection instead of a silently different certificate source.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`accepts_identity_and_remote_with_access_control`,
  `identity_without_key_is_rejected`, `unreadable_identity_certificate_is_rejected`,
  `unsupported_identity_issuers_are_rejected`); `crates/server/tests/admin_remote.rs`
  (`runtime_starts_remote_admin_beside_the_plaintext_listener` mints a CA and identity PEM pair with
  the `openssl` CLI and completes a mutual-TLS admin request).

## DIV-0140 — `admin.identity.identifiers` is schema-accepted but rejected when non-empty
- Status: out-of-scope
- Area: Admin / TLS
- Caddy behaviour: `identifiers` is the list of names or IP addresses for which the admin identity
  certificate is obtained (`external/caddy/admin.go:161-165`); certmagic issues or loads a
  certificate for them on demand, and `IdentityCredentials` errors only when the list is empty
  ("no identifiers configured").
- caddy-rs behaviour: the field is modelled (`AdminIdentity::identifiers`) so a Caddy configuration
  decodes and round-trips, but `validate_admin_identity` (`crates/core/src/validate.rs`) rejects any
  non-empty list with a located `admin.identity.identifiers` error: the identity comes from the PEM
  pair and caddy-rs never issues or selects a certificate by name. An empty or absent list is
  accepted: the PEM pair needs no name list, so upstream's "no identifiers configured" error (which
  guards its issuance path) has no counterpart here.
- Rationale: accepting and ignoring `identifiers` would silently serve a certificate unrelated to
  the requested names. A located error is the honest outcome while name-based admin issuance is out
  of scope (DIV-0139), and keeping the field in the typed model preserves JSON round-tripping while
  letting the error name the exact field.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`identity_identifiers_are_rejected`;
  `accepts_identity_and_remote_with_access_control` proves an absent list is accepted).

## DIV-0141 — `access_control[].subjects`/`serials` are caddy-rs selectors and advisory filters only
- Status: accepted
- Area: Admin
- Caddy behaviour: `caddy.AdminAccess` (`external/caddy/admin.go:197-210`) has only `public_keys`
  and `permissions`; identity is bound cryptographically by comparing each configured public key
  with the public keys of the certificates in `r.TLS.VerifiedChains`. A distinguished name or serial
  number is never consulted, and an unknown JSON field such as `subjects` is silently ignored by
  Go's decoder.
- caddy-rs behaviour: each entry also accepts `subjects` (Go `x509.Name.String()` form, for example
  `CN=client,O=ops`) and `serials` (decimal `big.Int.String()`), both caddy-rs extensions
  (`AdminAccess` in `crates/core/src/config.rs`). They are advisory filters over CA-chosen leaf
  metadata: `access_matches_identity` (`crates/admin/src/access.rs`) requires a `public_keys` match
  first and only then narrows it with the selectors, so an entry with selectors but no matching
  `public_keys` matches nobody and a spoofed subject DN from another configured CA never inherits
  permissions (tests `spoofed_subject_dn_from_another_ca_does_not_inherit_permissions`,
  `subject_selector_only_narrows_the_public_key_match`,
  `serial_selector_only_narrows_the_public_key_match`). Validation only checks shape — non-empty,
  no control characters for subjects; ASCII decimal digits for serials — with located errors.
  `subjects`/`serials` never authenticate a client on their own.
- Rationale: operators need to say "this key, but only the client certificate whose CN is X"; a
  modelled, explicitly documented filter is safer than upstream's silent ignoring of the fields, and
  keeping the selectors strictly narrowing means they can never weaken the key-material check.
- Tracking: T-COMPAT-003
- Test: `crates/admin/src/access.rs` unit tests, `crates/admin/tests/access_identity.rs` (4 tests
  over the fixture certificates in `crates/admin/testdata/access-control/`), and
  `crates/core/src/validate.rs` (`malformed_selector_is_rejected`,
  `accepts_identity_and_remote_with_access_control`).

## DIV-0142 — `access_control` permissions are validated strictly and `public_keys` must be X.509 DER at load
- Status: accepted
- Area: Admin
- Caddy behaviour: `enforceAccessControls` (`external/caddy/admin.go:678-757`) and
  `adminPathAllowed` (`external/caddy/admin.go:760-775`) compare request paths lexically with `path.Clean` and a
  path-segment prefix rule. `replaceRemoteAdminServer` (`external/caddy/admin.go:560-569`) does
  check each permission path that is neither empty nor `/` for canonical form (`path.Clean` plus a
  canonical trailing slash) and fails listener setup with `path %q is not canonical (did you mean
  %q?)`; it has no absolute-path rule, so a relative `config` is accepted, `methods` are never
  validated, and `public_keys` are base64/DER-decoded only when the listener's client pool is built.
  That pool is built by `replaceRemoteAdminServer` (`external/caddy/admin.go:512-624`), which is
  called from `Load` (`external/caddy/caddy.go:605`), so a broken key does fail the load in upstream
  Caddy as well — but as an unlocated listener-setup error rather than a validation error naming
  the field.
- caddy-rs behaviour: `validate_admin_access`, `validate_admin_permission` and
  `validate_admin_public_key` (`crates/core/src/validate.rs`) validate at load with JSON-path-located
  errors. Each `public_keys` entry must be base64 DER that parses as an X.509 `Certificate`, so a
  bare DER SEQUENCE such as `30 03 02 01 01` is rejected with "not a DER X.509 certificate". A
  permission path that is neither empty nor `/` must start with `/` and be canonical: a relative
  path, `.`/`..` segments, duplicate separators or other non-canonical spellings are rejected with
  the cleaned suggestion (an allowed trailing slash is preserved, matching upstream's rule). Each
  method must be an RFC 9110 token (`GET`, `POST`, `PATCH`, ...). Runtime matching then ports
  `adminPathAllowed` exactly (`admin_path_allowed`, `crates/admin/src/access.rs`) and keeps Caddy's
  `401` ("client identity not authorized") and `403` path/method messages plus the union-of-entries
  rule.
- Rationale: a path, method or key that can never match is a configuration bug; failing at load names
  the index and the offending value, whereas accepting it turns an access-control mistake into a
  runtime 401/403 that looks like a client problem. The canonical check mirrors upstream; the
  absolute-path requirement and the method-token check are the additions, and parsing keys at load
  means a broken trust anchor is reported before a listener starts.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`non_canonical_permission_path_is_rejected`,
  `relative_permission_path_is_rejected`, `invalid_method_is_rejected`,
  `malformed_public_key_is_rejected`, `non_certificate_der_public_key_is_rejected`),
  `crates/admin/src/access.rs` path/method unit tests, `crates/admin/tests/access_identity.rs`.

## DIV-0143 — `admin.remote` without any `public_keys` is rejected at validation
- Status: accepted
- Area: Admin
- Caddy behaviour: `replaceRemoteAdminServer` (`external/caddy/admin.go:512-624`) builds the
  client-certificate pool from the `public_keys` of every access-control entry. With an identity but
  none configured the pool is empty, the TLS server rejects every client certificate during the
  handshake, and the configuration itself is accepted and the listener starts. A remote endpoint
  without a certificate cache at all fails during `Load` (`external/caddy/caddy.go:605`) with the
  unlocated error "cannot enable remote admin without a certificate cache"
  (`external/caddy/admin.go:575`), i.e. at listener setup rather than as a validation error that
  names the empty field.
- caddy-rs behaviour: `validate_admin_remote` (`crates/core/src/validate.rs`) rejects the
  configuration with a located error when `access_control` is empty, when no entry lists a
  `public_keys` certificate, when `admin.identity` is absent, or when the identity has no PEM
  `certificate`/`key` pair. The first two are structural: rustls refuses to build a
  `RequireAndVerifyClientCert` verifier without trust anchors, so the listener could not start, and
  an entry naming only `subjects`/`serials` can never authorize (DIV-0141), which makes the
  list-level `public_keys` check the one that guarantees a usable trust pool.
- Rationale: upstream's accept-and-refuse-every-handshake turns a missing trust anchor or identity
  into a TLS error the operator debugs from the client side; a located load error names the empty
  field. Fail-closed behaviour is preserved either way.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`access_control_without_public_keys_is_rejected`,
  `remote_without_access_control_is_rejected`, `remote_without_identity_is_rejected`),
  `crates/server/tests/admin_remote.rs`.

## DIV-0144 — `admin.remote.listen` must be a concrete TCP address
- Status: out-of-scope
- Area: Admin
- Caddy behaviour: `RemoteAdmin.Listen` "accepts placeholders"
  (`external/caddy/admin.go:186-190`) and is resolved through `parseAdminListenAddr` at
  `external/caddy/admin.go:535` (defined at `:1435`) with the `:2021` default; the shared listen-address parser also
  accepts `unix/` and other networks, and the address is bound after placeholder replacement.
- caddy-rs behaviour: `validate_admin_remote` (`crates/core/src/validate.rs`) parses `listen`
  (default `:2021`, `AdminRemote::DEFAULT_LISTEN`) with `ListenAddr::parse_at` and rejects a
  non-TCP network with a located `admin.remote.listen` error. Because `ListenAddr` requires a
  literal `host:port`, a placeholder such as `:{remote_port}` is a located listen error as well, and
  `bind_admin_remote` (`crates/server/src/listeners.rs`) re-checks the TCP network before binding.
  The remote admin endpoint therefore needs a concrete TCP address in the configuration; the
  plaintext `admin.listen` uses the same concrete-address parser (`validate_admin_listen`), so it
  rejects placeholders for the same reason while keeping its Unix-socket support.
- Rationale: placeholders are expanded per request or per generation for HTTP listeners, but the
  remote admin listener is bound once at apply time with no request context to expand against;
  supporting them would need Caddy's global placeholder machinery for a control surface that
  normally has a fixed port. Rejecting the shape at load is loud and keeps the bound address
  inspectable.
- Tracking: T-COMPAT-003
- Test: `crates/core/src/validate.rs` (`non_tcp_remote_listen_is_rejected`; the `:2021` default is
  asserted in `accepts_identity_and_remote_with_access_control`). The runtime evidence in
  `crates/server/tests/admin_remote.rs` (binds a concrete `127.0.0.1:0` remote address) mints its
  certificates with the `openssl` CLI and returns early, without running the server, when that CLI is
  unavailable (`crates/server/tests/admin_remote.rs:220`), so it is environment-conditional; the
  validation itself is covered unconditionally by the `crates/core/src/validate.rs` tests.

## DIV-0145 — Remote-admin identity matching pins the leaf SPKI or re-verifies the chain to a configured anchor
- Status: accepted
- Area: Admin / TLS
- Caddy behaviour: `enforceAccessControls` (`external/caddy/admin.go:686-712`) walks every chain in
  `r.TLS.VerifiedChains` and every certificate in each chain, the trust anchor included, and
  compares its `crypto.PublicKey` with each configured `public_keys` entry; a match anywhere in a
  verified chain recognizes the key, and the documented contract is "any of these public keys can
  appear in any part of a verified chain".
- caddy-rs behaviour: rustls `peer_certificates()` omits the trust anchor, so `public_key_matches`
  (`crates/admin/src/access.rs`) matches when either the configured certificate's
  SubjectPublicKeyInfo equals the presented leaf's (`leaf_spki_matches`, leaf only — the
  configured-leaf anchor case, which WebPKI cannot express because it rejects an anchor that is
  itself the end entity), or `caddy_rs_tls::chain_anchored_by` (`crates/tls/src/client_auth.rs`)
  re-verifies the presented chain against the configured certificate as a single trust anchor with
  WebPKI path validation (`ALL_VERIFICATION_ALGS`, `KeyUsage::client_auth()`, current time).
  Configured roots and intermediates are covered through the second path, including an intermediate
  the client does not present, because every configured certificate is a root in the trust pool in
  both implementations. Certificates the client appends after the leaf are never inspected by key:
  they are not proven path members, so appending another entry's public certificate cannot borrow
  its permissions. The observable difference from upstream is narrow and deliberate: matching
  re-verifies at request time with the current clock instead of reusing the handshake-time
  `VerifiedChains`, so a client certificate that expires (or loses algorithm acceptability) between
  the handshake and a later request on the same connection is denied on that request, which is
  stricter than Caddy. One further difference follows from matching by key equality here versus
  matching by parsed key there: upstream recognizes a configured certificate when its public key
  appears anywhere in a verified chain, even if the configured certificate itself is not a usable
  trust anchor (its DER, subject, extensions or basic constraints differ from the chain element), while
  caddy-rs authorizes it only through leaf-SPKI equality when it is the presented leaf, or when it
  passes WebPKI path validation as the configured anchor. A configuration that pins a re-issued
  certificate sharing a verified chain element's key can therefore match in Caddy and be denied here;
  this is narrower, not looser, and a mis-pinned certificate fails closed.
- Rationale: binding identity to proven key material — the verified leaf's SPKI plus a successful
  path validation to the configured anchor — removes the "append someone else's CA certificate"
  escalation path that a key scan over client-supplied certificates would open, and makes the trust
  decision explicit and testable. The stricter request-time re-verification is documented rather
  than claimed as exact parity.
- Tracking: T-COMPAT-003
- Test: `crates/admin/tests/access_identity.rs`
  (`configured_leaf_anchor_binds_to_the_key_not_the_subject_dn`,
  `appended_foreign_ca_certificate_does_not_grant_that_entry`,
  `configured_intermediate_anchor_authorizes_only_the_leaves_it_issued`,
  `copied_subject_dn_from_another_configured_ca_gets_403_not_identity_permissions`),
  `crates/admin/src/access.rs` unit tests, and the `chain_anchored_by` tests in
  `crates/tls/src/client_auth.rs`.

## DIV-0146 — Admin Unix-domain sockets are bound owner-only 0600, and a changed `admin.listen` rebinds them
- Status: planned
- Area: Compatibility / Admin
- Caddy behaviour: Caddy v2.11.9 (`external/caddy`, commit `0d98cae`) accepts a `unix/` address in
  `admin.listen`, parses an optional `|<octal mode>` suffix through
  `internal.SplitUnixSocketPermissionsBits` (default mode `0200`, `u=w,g=,o=`; `connect(2)` needs
  write, which `0200` grants only to the owner), and binds the socket with that mode. The admin
  listener survives an unchanged `admin.listen` across reloads (the fd is duplicated into the new
  config), and on a changed address Caddy binds the new listener first and stops the old one
  asynchronously. The socket file is removed on shutdown.
- caddy-rs behaviour: `admin.listen` accepts `unix/<absolute path>` only. The `|<octal mode>` suffix
  is not parsed: it stays in the path, so `unix//run/admin.sock|0600` validates and binds a literal
  `/run/admin.sock|0600` file with mode `0600` instead of mode `0600` on `/run/admin.sock` — a silent
  approximation tracked by `T-ADMIN-062` (reject loudly or implement). The socket is bound `0600`
  (owner read+write; the Caddy default `0200` is owner write-only, so both are owner-only for
  `connect(2)` and the observable difference is the owner read bit/file mode). A stale socket file at
  the path is unlinked before bind (never an inherited systemd socket — the admin bind has no
  `LISTEN_FDS` path; socket activation covers `apps.http` listeners only), and the file is removed on
  shutdown. A reload keeps the listener when `admin.listen` is unchanged; when it changes, caddy-rs
  stops and removes the old listener before binding the new one (a brief gap) instead of Caddy's
  bind-new-then-async-stop-old order. `reload`/`stop` reach the socket through the `unix//path`
  admin address (`crates/server/src/listeners.rs` `bind_admin_unix`/`admin_unix_tests`,
  `crates/server/src/runtime.rs` `reconcile_admin`).
- Rationale: `0600` keeps the admin endpoint owner-only (the reason to choose a Unix socket over a
  loopback TCP port) and additionally lets the owner read/identify the socket file; the difference
  from Caddy's `0200` default is the owner read bit and the observed mode, not cross-user reach.
  Rebinding on an address change is the lifecycle the reload path already owns and keeps the socket
  file consistent with the new config; the gap is bounded and only occurs when the address changes.
  Those two differences are permanent documented choices; the unparsed `|<mode>` suffix is the
  planned gap: binding it as part of the path is a silent approximation, not an advertised outcome,
  and `T-ADMIN-062` closes it by rejecting loudly or implementing Caddy's suffix semantics.
- Tracking: T-COMPAT-003
- Test: `crates/server/src/listeners.rs` (`admin_unix_tests`, including the `0600` mode assertion),
  `crates/server/tests/admin_unix.rs` (`unix_admin_serves_the_api_and_the_socket_is_removed_on_shutdown`,
  `reload_from_unix_to_tcp_removes_the_socket`, `reload_from_tcp_to_unix_creates_a_working_socket`,
  `reload_between_unix_paths_cleans_the_old_socket`), and
  `crates/cli/tests/cli.rs` (`reload_and_stop_reach_a_unix_socket_admin_endpoint`). The unparsed
  `|<mode>` suffix has no test yet; `T-ADMIN-062` adds the loud rejection (or parsing) and its test.

## DIV-0148 — Radar is a caddy-rs global option with no Caddy equivalent, and its runtime wiring is still planned
- Status: planned
- Area: Compatibility / Radar
- Caddy behaviour: Caddy v2.11.9 (`external/caddy`, commit `0d98cae`) has no Radar threat-intelligence
  feature: `caddyconfig/httpcaddyfile` registers no `radar` global option, so the adapter rejects it as an
  unrecognized global option, and the strict top-level JSON loader has no `radar` field.
- caddy-rs behaviour: `radar` is a caddy-rs extension (ADR-0020). The Caddyfile adapter parses a global
  `radar { ... }` option — `mode` (`auto` default: idle until the first Internet-routable client IP; `on`:
  poll from startup; `off`: behave as if absent), `protect` (boolean, default `true`), optional
  `api_token`, `poll_interval` (Go duration, default `60s`, minimum `30s`), `cache_ttl` (Go duration,
  default `120s`), `storage` (`type` `file` with optional `path` (default), `redis` with optional
  `redis_url`/`key_prefix`, or `memory`), `endpoints` (`ddos_l7`/`ddos_l34`/`bgp_hijacks`/
  `traffic_anomalies`, all default `true`) and `filters` (`min_magnitude` non-negative integer,
  `countries` ISO 3166-1 alpha-2 list, `asns` integer list; omitted when empty) — and emits a top-level
  `"radar"` object with Go-duration strings and an explicit `storage.type`, `api_token` omitted when unset
  (`crates/config/src/parser.rs` `parse_radar_option`, `crates/config/src/adapter.rs` `radar_json`). There
  is deliberately no `enabled` field: `enabled` is a located error naming `mode`, and duplicate
  sub-options, unknown sub-options, arguments on the option line and a sub-`30s` poll interval are located
  adaptation errors at the directive line. The runtime does not consume the emitted object yet: the typed
  top-level loader preserves it under unknown keys and validation rejects it with `unknown top-level
  configuration field(s): radar`, so an adapted configuration carrying the option cannot be loaded until
  `T-ROUTE-059` (polling client/storage) and `T-ROUTE-060` (matcher/variables/default protection) wire it;
  the emitted `storage.redis_url`/`key_prefix` spellings and the runtime `RadarConfig::from_json`
  `storage.url`/`prefix` spellings must be reconciled by that wiring. `stock_compat true` rejects the
  Caddyfile option as `config.unsupported` with ``global option `radar` (caddy-rs extension, not in Caddy
  v2.11.9)``; the global `trust_cdn` form is rejected the same way (`error[config.unsupported]`), while the
  `servers`-block `trust_cdn` form is refused by the adapter gate as `error[config.invalid]`: `` `servers`
  option `trust_cdn` (caddy-rs extension, not in Caddy v2.11.9) is not supported with `stock_compat true` ``
  (ADR-013; see [`STOCK-COMPAT.md`](STOCK-COMPAT.md)).
- Rationale: Cloudflare Radar threat data (ADR-0020) is the security feature the proxy profile is built
  around, so it must be opt-in, must not be silently portable to stock Caddy (where it would protect
  nothing), and its unwired state must fail loudly rather than appear to protect. `mode` instead of
  `enabled` keeps the auto-idle behaviour explicit and removes a flag that could contradict polling.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/radar.rs` (`empty_radar_block_adapts_to_the_documented_defaults`,
  `every_radar_field_maps_to_the_adr_json`, `mode_off_and_redis_and_memory_storage_map`,
  `no_enabled_key_is_ever_emitted`, `poll_interval_below_the_minimum_is_a_located_error`,
  `unknown_radar_sub_option_is_a_located_error`, `stock_compat_rejects_radar_and_trust_cdn`), plus the
  adapter/validator transcript in [`TESTING.md`](TESTING.md#radar-oracle-evidence-adr-0020-div-0148div-0150-t-compat-059).

## DIV-0149 — `@radar` matcher is a caddy-rs module with no Caddy equivalent
- Status: accepted
- Area: Compatibility / Radar
- Caddy behaviour: Caddy v2.11.9 has no `radar` HTTP matcher module: the Caddyfile adapter rejects a
  Caddyfile `@radar` block field by field (``matcher `source_asn_attacking` ``), and the JSON `match`
  loader rejects a `radar` matcher object as an unknown matcher module.
- caddy-rs behaviour: `crates/http/src/radar_matcher.rs` implements `RadarMatcher` over the cached
  `RadarSnapshot`: a `RadarPredicate` that is the AND of every field set — `source_asn_attacking`,
  `source_asn_attacking_l34`, `target_asn_attacked`, `source_asn_hijacking`, `target_prefix_hijacked`,
  `source_asn_leaking`, `source_asn_anomalous` (ASN selectors: `true` = the client's GeoIP ASN, a
  number/string = require the client to be that ASN, `false`/`null` = unset), `source_country_attacking`,
  `target_country_attacked` (`true` = the client's country, a string = require that country),
  `anomaly_type` (string or list; case-insensitive, `-`/space also match `_`), `min_magnitude` (inclusive;
  a record without a magnitude cannot satisfy it) and `max_age` (Go duration; an older snapshot matches
  nothing, and the whole snapshot is rejected rather than filtered). No field set means it never matches;
  with Radar disabled it matches nothing. A trusted-CDN peer resolves the client IP from the configured
  forwarded header, an untrusted peer uses its socket address. Unknown predicate fields are located
  errors. Registration: `http.matchers.radar` is registered in `crates/core/src/module.rs`, so a JSON
  `{"match":[{"radar":{...}}]}` builds instead of failing as `module.unknown`. Adapter: the Caddyfile
  form is a matcher directive — `@attacked { radar source_asn_attacking true }` or the inline
  `@attacked radar source_asn_attacking true` — whose `name value` pairs become the predicate object,
  with `true`/`false` kept as booleans because `RadarPredicate::from_json` is the single authority on
  each key's type; an empty predicate set, an odd number of inline arguments and a value-less block line
  are located errors. Wiring: the server supplies the runtime handles through
  `build_matcher_set_with(value, &MatcherDeps)`, with `build_matcher_set` retained as the
  default-deps wrapper for its one production caller, and `RouterBuilder::with_matcher_deps`.
  A `radar` matcher built without those handles is a located `match.radar` error rather than an
  installed matcher that could only match nothing, because a silently dead security matcher looks like
  it works. **What this does not do:** nothing polls Radar yet, so the `RadarState` the server
  constructs is always empty and every predicate is false in a running server — the matcher is
  reachable and evaluated, but matches nothing. `trust_cdn` resolves to `NoopTrustCdn`, so
  forwarded-header client-IP recovery is not implemented. `mode`, `poll_interval`, `cache_ttl`,
  `storage`, `endpoints` and `filters` are parsed and validated but consumed by no poller. Registration
  and wiring were delivered by queue task `T-ROUTE-065`, which is not a `plan/` task and so cannot
  appear in the Tracking field.
- Rationale: threat-intelligence predicates are only useful if they can match the operator's traffic, but a
  matcher that silently did nothing (or silently matched everything) would be a security hole; keeping it
  unregistered until the client and snapshot plumbing exist made the gap explicit and testable; now that
  registration and wiring have landed, the remaining gap — no poller, so the snapshot is empty — is
  stated above rather than left to be discovered. The AND-of-set shape is the smallest predictable
  predicate, and entry-level filters stay OR within their field.
- Tracking: T-COMPAT-003
- Test: `crates/http/tests/radar_matcher.rs` (`source_asn_attacking_requires_an_l7_attack_source`,
  `source_asn_attacking_l34_uses_the_l34_endpoint`, `source_country_attacking_uses_the_client_country`,
  `target_asn_attacked_uses_the_anomalies_endpoint`, `target_country_attacked_uses_the_anomalies_endpoint`,
  `source_asn_hijacking_requires_a_hijack_record`, `target_prefix_hijacked_keys_on_the_target_asn`,
  `source_asn_leaking_requires_a_leak_kind`, `source_asn_anomalous_covers_attack_and_anomaly_records`,
  `explicit_asn_and_country_selectors_constrain_the_client`,
  `anomaly_type_accepts_a_list_or_a_single_value`, `min_magnitude_is_inclusive`,
  `max_age_rejects_a_stale_snapshot`, `multiple_fields_are_anded`, `empty_predicate_never_matches`,
  `disabled_radar_matches_nothing`, `trust_cdn_forwarded_ip_is_used_only_for_trusted_peers`,
  `invalid_predicate_fields_are_rejected`); registration and wiring are covered by
  `crates/http/tests/radar_registration.rs` (7 tests), `crates/config/tests/radar_matcher_adapt.rs` (7),
  `crates/server/tests/http_radar_matcher.rs` (2) and the runtime's `matcher_deps_tests` (5).

## DIV-0150 — `{http.request.radar.*}` variables are a caddy-rs extension, not populated by the server yet
- Status: planned
- Area: Compatibility / Radar
- Caddy behaviour: Caddy v2.11.9 defines no `http.request.radar.*` placeholders, so a configuration using
  one carries the literal token (unknown placeholders are left unchanged by Caddy's replacer).
- caddy-rs behaviour: `crates/http/src/radar_vars.rs` defines exactly twelve names under the
  `http.request.radar.` prefix: `source_asn_attacking`, `source_asn_attacking_l34`,
  `source_country_attacking`, `target_asn_attacked`, `source_asn_hijacking`, `target_prefix_hijacked`,
  `source_asn_leaking`, `source_asn_anomalous`, `anomaly_types`, `attack_magnitude_l7`,
  `attack_magnitude_l34` and `data_age`. The ASN/ASN-set variables emit the client's ASN only when the
  corresponding predicate holds, `source_country_attacking` emits the upper-cased country code,
  `anomaly_types` emits comma-separated sorted deduplicated kinds, `attack_magnitude_l7`/`_l34` emit the
  highest reported magnitude as text, and `data_age` emits the snapshot age in whole seconds. Every
  variable is an empty string while Radar is disabled, while no snapshot is cached, for an unknown name,
  or when the client has no GeoIP identity — except `data_age`, which is reported as soon as a snapshot
  exists because it is computed before the client is identified; `RadarVars::populate` writes all twelve into `Request::vars`
  under their full names (from the matcher's `matches_mut` or the protection hook), so a `headers` handler,
  log field or `rate_limit` key later in the same request reads them through the normal replacer fallback,
  and `resolve_radar_variable` is the free-function form. The server request pipeline does not call either
  yet, so a placeholder in a `header`/`vars`/`log` configuration adapts as a literal token and expands to
  an empty string until `T-ROUTE-060` wires the client. The matcher field
  `target_country_attacked` has no companion variable: the twelve-name list is the contract.
- Rationale: the variables are how Radar data reaches hand-written policies (log enrichment, header
  decoration, rate-limit keys) without the operator parsing JSON in CEL; keeping the set small and the
  empty value unambiguous means a policy can distinguish "Radar knows nothing" from a false match, and an
  unwired variable fails closed (empty) rather than carrying stale data.
- Tracking: T-COMPAT-003
- Test: `crates/http/tests/radar_matcher.rs` (`matches_mut_publishes_request_variables`,
  `variables_report_each_name_for_a_known_client`, `variables_follow_the_client_attributes`,
  `variables_are_empty_when_radar_is_disabled`, `variables_are_empty_when_nothing_is_known`,
  `data_age_reports_snapshot_age`, `populate_writes_every_variable_and_the_free_function_agrees`); there
  is no dedicated `crates/http/tests/radar_vars.rs`, so these matcher tests are the variable evidence.

## DIV-0151 — the `setup` activation endpoint is a cleartext loopback HTTP listener, and the module exists only for a setup boot
- Status: accepted
- Area: Compatibility / Setup
- Caddy behaviour: Caddy v2.11.9 has no `setup` subcommand, no `/_caddy-pm/activate` route, no
  `caddy_rs.setup` module and no activation token store, so none of this surface exists upstream and
  there is no upstream behaviour to match.
- caddy-rs behaviour: a `caddy-rs setup` boot serves the single-use activation endpoint over plain
  HTTP on a loopback listener (`crates/cli/src/setup.rs`, `activation_listen`). With no
  `--listen-address` it binds `127.0.0.1:<port>`, and a host-less `:port` also resolves to loopback
  rather than the wildcard, so the temporary endpoint is never exposed on every interface. The
  generated configuration sets `apps.http.https_port = 0` because the `https://` activation URL
  printed by `setup` cannot be served without the `caddy-rs-pm` service that T-SETUP-004 provides;
  the endpoint is therefore cleartext until that lands, and the printed scheme is not TLS. The
  activation module is registered only for a setup boot and is not added to `BUILTIN_MODULES`, so a
  normal `run` does not expose it; the stock-compatibility profile rejects `setup` before the boot,
  keeping the rejection ahead of any activation surface.
- Rationale: an activation token is a one-shot credential minted locally by the operator's own
  `setup` invocation, so binding it to loopback keeps the window where a live token is redeemable off
  the network entirely; refusing the wildcard spelling closes the case where an operator writes
  `:8443` expecting loopback and silently publishes the endpoint. Serving cleartext is an honest
  consequence of the service that would terminate TLS not existing yet, recorded here rather than
  left implicit, and registering the module only for a setup boot means the endpoint cannot be reached
  by a deployment that never ran `setup`.
- Tracking: T-COMPAT-003
- Test: `crates/cli/tests/activation.rs`
  (`the_activation_listener_is_loopback_by_default` proves the no-flag and host-less `:port` cases bind
  loopback while an explicit host is honoured, `the_activation_listener_answers_over_tcp` proves the
  endpoint is reachable over the loopback listener, `a_response_body_never_contains_the_token` and
  `every_outcome_renders_status_headers_and_body` cover the response contract);
  `crates/cli/tests/setup.rs` proves the generated configuration carries `https_port = 0`.

## DIV-0152 — `setup --auth-method totp` enrols an in-memory credential; `webauthn` is refused rather than faked
- Status: accepted
- Area: Compatibility / Setup
- Caddy behaviour: Caddy v2.11.9 has no `setup` subcommand, no `/setup/_caddy-pm/activate` route and no
  TOTP or WebAuthn enrollment ceremony, so neither the flow nor its persistence has an upstream
  counterpart to match.
- caddy-rs behaviour: redeeming a setup activation link opens a two-step TOTP enrollment behind that
  same single-use token (`crates/cli/src/enrollment.rs`, wired through
  `ActivationService::handle_async`). The `begin` step mints a secret through
  `caddy_rs_authn::AuthnService::totp_setup` and returns the `otpauth://` URI once and only to the
  holder of the live link; it is idempotent within one activation so a refresh cannot invalidate a
  secret already scanned. The `verify` step proves possession through `totp_verify`, which applies the
  ±1 step window and monotonic step record, so a replay or a downgrade to an older code is reported as
  `code_replayed` rather than a mismatch. A correct code enrols exactly one admin credential and closes
  the window: every later request, whatever token it presents, is refused with `already_enrolled`. The
  link admits the enrollment *session* rather than each request — the first step consumes the token and
  only that same token may continue it, checked before the token store is touched so a second minted
  token cannot join. The enrolled credential lives in process memory and does not survive a restart;
  persistence is `T-SETUP-005`. `--auth-method webauthn` enrols nothing in this build and every
  enrollment request is refused with `501 method_unsupported` naming `T-SETUP-010`.
- Rationale: enrollment is the step that turns the activation link into a credential, so serving it
  from the same single-use token keeps the window in which either is live identical to the window in
  which the link is live. Consuming per-request would break the two-step flow, and consuming per-session
  without binding the session to the opening token would make any minted token a credential, so the
  session is bound to the exact token that opened it. The secret is returned once and never logged
  because it is the credential itself. Refusing `webauthn` with a named tracking task is deliberate:
  WebAuthn needs an attestation ceremony, an authenticator response parser and a writable credential
  store that do not exist in this workspace, and a credential that reported success without them would
  be worse than one that says it cannot yet. In-memory storage is recorded here rather than hidden
  because a credential that vanishes on restart must not be discovered by surprise.
- Tracking: T-COMPAT-003
- Test: `crates/cli/tests/enrollment.rs`
  (`a_correct_code_enrolls_exactly_one_credential_and_closes_the_window` proves the exactly-once rule
  and the closed window, `a_wrong_code_is_refused_and_does_not_enroll` proves a bad proof is not
  terminal but also not an enrollment, `a_code_from_an_older_step_is_refused_once_a_newer_one_is_used`
  proves a stale code cannot be used, `webauthn_is_refused_rather_than_faked` proves the `501`, and
  `a_different_token_cannot_continue_another_tokens_enrollment_session` proves the session is bound to
  the opening token; `totp_enrollment_completes_over_the_real_listener` drives the whole flow over the
  real activation listener, so an unwired service cannot pass).

---

## DIV-0153 — outbound TCP with a pinned source address reserves a unique local 2-tuple at `bind()` time, capping concurrent upstream connections

- Status: open
- Area: Reverse proxy / outbound transport
- Caddy behaviour: Caddy v2.11.9 does not pin an outbound source address of its own, so its reverse-proxy dial takes Go's default path and the kernel chooses both the source address and the source port at `connect()`; Linux may then share the `{src_ip, src_port}` 2-tuple across distinct destinations, and the concurrent-connection ceiling is the ephemeral range *per destination*. When an operator sets `transport.local_address`, Go's `net.Dialer` performs `bind()` before `connect()` at the syscall level and sets no socket option, so Caddy has the same 2-tuple-reserving behaviour as this program — the difference is not that Caddy is better, it is that this program names the consequence and closes it. Verified in the pinned oracle: `modules/caddyhttp/reverseproxy/httptransport.go:233-245` resolves `dialer.LocalAddr` with `netaddr.JoinHostPort(0)` (port 0 always — Caddy offers no explicit source-port form), and Go 1.26 `src/net/sock_posix.go` `sktPosix` calls `syscall.Bind` then `fd.connect` with no `IP_BIND_ADDRESS_NO_PORT` in either `setDefaultSockopts` or the bind path.
- caddy-rs behaviour: a configured `transport.local_address` reaches `connect_address` (`crates/proxy/src/client.rs:1008-1021`), which creates a `TcpSocket`, calls `bind(local)` and then `connect`. Because `bind()` must reserve a unique local 2-tuple — the kernel cannot know the socket will not be `listen()`ed — each concurrent outbound connection from that source address holds its own ephemeral port and the port cannot be shared across destinations the way an unbound `connect()` allows. The ceiling is therefore `net.ipv4.ip_local_port_range` (28 232 ports at the default 32768-60999) counted over *distinct ports in use*, not per destination: before this change the process gets one port per concurrent connection summed across all upstreams, whereas a vanilla `connect()` lets one source port serve several destinations at once. Note this is the same kernel path Caddy takes when its own `local_address` is set, so the difference is in what the operator asked for, not in the mechanism. Exhaustion fails every new outbound connection in the process, including the process's own ACME/OCSP and DNS traffic. With no `local_address` configured, the dial takes `TcpStream::connect` and is unaffected. ADR-0043 closes this: with a port-0 local address the helper sets `IP_BIND_ADDRESS_NO_PORT` before `bind()` so the kernel defers the port choice to `connect()` and may share it (`EADDRNOTAVAIL` on exhaustion, not `EADDRINUSE`); with an explicit source port, where `IP_BIND_ADDRESS_NO_PORT` is invalid, it sets `SO_REUSEADDR` before `bind()` and surfaces a contended port as a named, located error rather than a silent fallback. The option is Linux-gated and the non-Linux fallback stays the behaviour described above until that port exists.
- Rationale: `bind()`-before-`connect()` is the documented cause of the limit (see `IP_BIND_ADDRESS_NO_PORT(2const)`, Linux 4.2+: the port is "automatically chosen at connect(2) time, in a way that allows sharing a source port as long as the 4-tuple is unique"), and an operator who pins a source address for outbound IP separation — the normal high-volume deployment — silently forfeits source-port sharing. The alternative of leaving it unregistered would make a self-inflicted capacity limit indistinguishable from a kernel limit.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/client.rs` unit tests assert per case which option the egress helper sets and that `bind` precedes `connect`, failing against the pre-change code. Case (b)'s behavioural proof is `port_zero_local_address_leaves_the_source_port_unreserved_until_connect`: after `bind(local, 0)` the socket's port is still 0, i.e. the 2-tuple is not yet reserved and the kernel defers the choice to `connect()` — this is the observable that distinguishes the fix from the pre-change code and it fails there (mutant measurement: port 35499 instead of 0). `a_deferred_source_port_is_chosen_by_connect_and_the_dial_completes` shows the deferral leaves the dial working and that the listening peer observes the source port `connect()` chose, with a loud skip if the sandbox cannot bind a loopback listener. The explicit-port conflict test `contended_explicit_source_port_names_the_local_address_and_port` asserts the named error carries the local address and destination. **Correction (T-PROXY-065):** this field previously described the case-(b) test as opening many concurrent connections and asserting a *shared* source port. That is not observable: with and without the option alike, concurrent outbound connections from a port-0 pinned source take distinct ports, so the assertion would fail on correct code. The field now names the reserve-vs-defer proof the kernel actually supports; the capacity consequence is bounded by ADR-0043 §4 (a budget, not a promise).

## DIV-0154 — outbound connected UDP is bounded by the ephemeral port range and caddy-rs does not adopt a port-sharing workaround

- Status: accepted
- Area: Reverse proxy / outbound transport (UDP)
- Caddy behaviour: Caddy v2.11.9 does not set `SO_REUSEADDR` on its outbound connected UDP sockets (for example the DNS resolver's), so Linux looks for a unique local 2-tuple at `connect()` and the total number of concurrent connected UDP sockets per protocol is bounded by the ephemeral range even across multiple destinations, with `EAGAIN` on exhaustion. Caddy offers no configuration for this and no workaround.
- caddy-rs behaviour: the same bound applies and is the accepted behaviour. **Every** outbound UDP site in the implementation is enumerated here, and the list is exhaustive as of `T-PROXY-066` (a mechanical `grep -rn 'UdpSocket::bind' crates/` filtered to non-test, non-loopback binds yields exactly these two):
  1. the DNS resolver's datagram exchange, `crates/proxy/src/dns.rs`, which binds `0.0.0.0:0` inside the single helper `bind_egress_udp` and then `connect`s; its TCP fallback on truncation is out of scope for this bound because it is TCP;
  2. the admin/metrics push sink's UDP transport, `crates/admin/src/sink.rs`, which likewise binds `0.0.0.0:0` and `connect`s to the configured `address` for `NetProtocol::Udp`.
  **No egress UDP socket in either site sets `SO_REUSEADDR`, and no port-sharing workaround is applied anywhere in the program** — a test pins this by asserting `dns.rs`'s production half contains exactly one `UdpSocket::bind` (`bind_egress_udp`) and no code reference to the option, so adding a second constructor or enabling the option fails the suite. The exhaustion path is required to be loud: the resolver's bind and connect errors name the resolver address and the ephemeral-port bound rather than a generic "connecting DNS UDP socket" wrapper. **Measured, not assumed:** exhausting the range by holding 28 232 `0.0.0.0:0` UDP sockets (matching the default `32768-60999` exactly) makes the next bind fail with `EADDRINUSE`, errno 98 — *not* `EAGAIN` — so the errno-98 case is the one the loud path must cover, and it does. The userspace `connectx` technique for UDP — `SO_REUSEADDR` around `bind()`, cleared to act as a cooperative lock, 4-tuple ownership checked through netlink `SOCK_DIAG_BY_FAMILY` against `SO_COOKIE`, then `connect()` and re-enable — is deliberately not adopted (ADR-0043 §3): two connected UDP sockets are permitted to share a full 4-tuple and the newer one silently overshadows the older, so one upstream can silently receive traffic meant for another; the technique also depends on undocumented kernel behaviour and on cross-process cooperation the program cannot enforce, and `libc` 0.2.189 exposes no `SOCK_DIAG_BY_FAMILY`, no `INET_DIAG_REQ_V2` and no request structs. What is pursued instead is fewer connected UDP sockets per flow and upstream connection reuse.
- Rationale: this program's first principle is that unsupported behaviour fails by name, never silently degrades. A port-sharing scheme whose failure mode is silent mis-delivery between upstreams trades a loud, recoverable capacity limit for a security defect (route/tenant confusion), and the alternative is not merely undocumented but unfalsifiable from inside one process. The ceiling is published to operators with the commands that measure it rather than papered over.
- Tracking: T-COMPAT-003
- Test: `crates/proxy/src/dns.rs` asserts that the resolver's bind and connect message formatters name the resolver address and, for the exhaustion error kinds, the ephemeral-port bound, and that non-exhaustion errors do NOT claim the port range; that `udp_exhaustion_hint` fires for the measured errno 98 (`from_raw_os_error(98)`, tied to the platform rather than to a guessed `ErrorKind`); and that `dns.rs`'s production half contains exactly one `UdpSocket::bind` with no code reference to `SO_REUSEADDR` (the assertion fails if a second constructor or the option is added). It does NOT assert anything about `crates/admin/src/sink.rs`'s UDP transport, which remains unguarded — T-PROXY-068 covers that. The resolver's UDP/TCP exchange tests continue to cover the truncation fallback.

## DIV-0155 — caddy-rs offers an opt-in graceful process restart (binary upgrade); Caddy has no equivalent

- Status: open
- Area: Process lifecycle / restart and upgrade
- Caddy behaviour: Caddy v2.11.9 has no graceful process restart. It installs a handler for `SIGHUP` and then does nothing with it — `external/caddy/sigtrap_posix.go:81-84` logs `"not implemented"` for `syscall.SIGHUP` with the comment that the signal "is sometimes sent outside of the user's control", so `SIGHUP` is effectively ignored. Upgrading the Caddy binary therefore requires stopping the process, which closes the listening sockets (refusing new connections for the gap) and terminates every established connection. Caddy's graceful behaviour applies to *configuration reload* within one process, which caddy-rs already matches; it does not extend to replacing the binary.
- caddy-rs behaviour: caddy-rs keeps the same in-process reload behaviour, and additionally offers an **opt-in** process-level graceful restart that Caddy does not have at all. When enabled, the running process forks and execs the new binary, passing the listening sockets as inherited file descriptors; the old generation keeps accepting until the child signals readiness, so there is no gap in listening, and it then closes its listener copies and drains existing connections under the configured grace period. This is implemented with `ecdysis` (v1.1.1, Apache-2.0) behind a default-off Cargo feature plus an explicit runtime flag, is Unix-only (fork/exec and fd passing are unavailable on Windows, where the feature fails loudly rather than degrading), and preserves the existing meaning of `SIGINT` and `SIGTERM`. Because Caddy has no equivalent, this is an extension and is deliberately **not** presented as parity.
- caddy-rs behaviour — in-memory state across the two-generation window (measured by `T-CORE-116`): only inherited file descriptors cross `exec`. `crates/server/src/graceful_restart.rs` serialises no state for the child and the child builds a fresh `ServerRuntime` (`crates/cli/src/main.rs:1161`, under `Command::Run` at `:1043`), so **every in-memory store starts empty in generation 2 while generation 1 still serves its drain**. The stores were enumerated by file and symbol rather than assumed, and each is classified below. *Accepted as lost* — the operator-visible consequence is that the counter or cache restarts at zero, and the restart is already the visible event: **metrics counters** (`crates/admin/src/metrics.rs:244` `MetricsRegistry`, owned by `AdminApi` at `crates/admin/src/lib.rs:797`, which `ServerRuntime::new` constructs at `crates/server/src/runtime.rs:417` — so counters reset to zero and two live registries coexist during drain, each rendering only its own generation's series); **in-memory rate-limit buckets** (`crates/http/src/rate_limit.rs:134` `LimiterState` behind `TokenBucketLimiter` at `:139`, owned per handler by `RateLimitHandler` at `:270` and constructed in `crates/http/src/router.rs:847` — so every bucket is rebuilt empty and a restart **resets every rate-limit window**, letting a client that had exhausted its budget spend a fresh budget; this is the one loss with a security-adjacent consequence and is stated here rather than left implicit); the **Radar cache** (`crates/http/src/radar_matcher.rs:317` `RadarState`, built per matcher-deps at `crates/server/src/runtime.rs:2074` — the snapshot is empty on both generations today because no poller exists, so the restart changes nothing observable yet); the **proxy upstream source cache** (`crates/proxy/src/dynamic_upstreams.rs:147` `SourceCache` with `CacheEntry` at `:154`, one per handler at `:246`/`:308` and `:383`/`:431`) — DNS-expanded upstreams are re-resolved, costing a lookup burst, never serving stale data; the **PKCS#11 module registry** (`crates/tls/src/pkcs11.rs:1507` `MODULE_CONTEXTS`), which is deliberately process-lifetime and is torn down by `C_Finalize` at exit, so the child re-runs `C_Initialize` per token — correct, and only a startup cost; and the **adaptive ACME challenge selector** (`crates/tls/src/acme/adaptive_challenge.rs:260` `GLOBAL`), whose recorded `record_offered`/`record_attempt` success history is lost, so the learned challenge preference restarts from `DEFAULT_UNIVERSE`; the issuance path uses a per-issuer selector instead, so this affects standalone callers only. *Accepted, no consequence* — process-local bookkeeping that must not survive: the signal counters (`crates/cli/src/signals.rs:22` `SIGNAL_COUNT`, `:26` `RESTART_COUNT`, feature-gated), the pid/entry counters (`crates/core/src/autosave.rs:377`/`:430`, `crates/core/src/data_dir.rs:522` `PROBE_SEQUENCE`, `crates/http/src/radar_store.rs:323` `TEMP_SEQUENCE`, `crates/tls/src/storage.rs:704` `TEMPORARY_COUNTER`), the per-connection WebSocket/HTTP hash seeds (`crates/proxy/src/websocket.rs:269`, `crates/server/src/http.rs:844`, `crates/proxy/src/dns.rs:272` `COUNTER`), the udpgrm pending registry and absent latch (`crates/server/src/udpgrm.rs:361` `PENDING`, `:398` `ABSENT`), the bindcap counters (`crates/server/src/bindcap.rs:348` `CAPABILITY_OPERATIONS`), the access-log regex cache (`crates/admin/src/access_log.rs:1555` `CACHE`, recompiled on demand), the radar client's rustls config (`crates/http/src/radar_client.rs:750` `CONFIG`, rebuilt on demand), and the l4 proxy start instant (`crates/l4/src/handlers/proxy.rs:159` `START`). *Must be made restart-aware* — exactly one, and it is a safety decision rather than a cache: the **PKCS#11 signing quarantine** (`crates/tls/src/pkcs11.rs:462` `GLOBAL_QUARANTINE`). This latch is set on the production signing path — `set_quarantined` at `:554` calls `quarantine()` from the sign-timeout and session-gone arms at `:695` and `:702` — and it is consulted on the dispatch loop at `:1216` and rejects signing at `:652` with `Pkcs11Error::Quarantined`. It is process-lifetime and never serialised, so **a graceful restart silently clears it**: a token deliberately stopped because the HSM failed to answer a dispatched signature is signed through again by the new generation, and the operator-visible event is a restart, not a recovery of the token. Unlike every other store in this inventory, its correct post-restart value is **not** its initial value — the latch records a hardware failure that a `fork`/`exec` does not repair — so it is the one store that must be made restart-aware rather than accepted as lost. Until it is, the consequence is stated here: **a restart re-admits a quarantined signing token**. Making it restart-aware is queued as queue task `T-90d0507d` — a queue task rather than a `plan/` one, so it is named in this prose and not in the Tracking field below, which cites only ids that resolve in `plan/`. The other stores need no reconciliation, because each is a cache, a counter, or a per-request bookkeeping value whose correct post-restart value is its initial value. The other loss that merits attention is the **rate-limit window reset**, which is a real security-adjacent consequence rather than a cosmetic counter reset; it is recorded here as accepted-for-v1 with the consequence stated, and reconciling it across generations is deliberately **not** implemented by this task (see `T-CORE-116`). Sibling inventory: `T-PM-141` covers the proxy manager's state directory, a **different process**; the stores above are caddy-rs-specific, and the two inventories are siblings rather than alternatives.
- Rationale: stop-then-start upgrades are the exact failure mode that costs live connections and refused requests, and the program should be able to ship a security patch without a maintenance window. The alternative that first suggests itself — `SO_REUSEPORT` so both generations can bind — is rejected: the kernel load-balances across separate listening sockets, so a connection already queued in the dying generation's accept queue is orphaned and reset, which is a worse and quieter failure than the gap it removes. Fork-plus-inherited-fds is the long-established alternative (NGINX, tableflip) and keeps exactly one kernel socket. It is opt-in because an inherited-fd server behaves differently under supervisors and in containers, and because the stock-compatibility profile and reproducible builds must stay unchanged. The restart trigger is authorized exactly like `POST /load` with no new bypass, since an attacker-triggerable restart is a denial-of-service primitive.
- Tracking: T-COMPAT-003
- Test: `T-CORE-104`'s harness (`crates/cli/tests/zero_downtime_restart.rs`) drives connections through a graceful restart and asserts zero resets and zero refusals, with a `SIGKILL` control that proves the counters can detect an outage; a child that fails initialisation leaves the parent serving; a second upgrade during an in-flight upgrade is refused; a canary file descriptor proves only listener and pipe fds cross `exec`; and `pm/crates/pm-cli/src/main.rs`'s `the_unit_advertises_reload_because_the_daemon_now_handles_sigusr2` asserts that the systemd unit advertises `ExecReload=/bin/kill -USR2 $MAINPID` and no longer uses `HUP`, so `systemctl reload` reaches the daemon instead of killing it.

## DIV-0156 — caddy-rs offers an opt-in graceful restart for the UDP/QUIC path, requiring the external `udpgrm` daemon; Caddy has no UDP graceful restart at all

- Status: open
- Area: Process lifecycle / restart and upgrade (UDP, QUIC/HTTP-3)
- Caddy behaviour: Caddy v2.11.9 has no graceful restart of any kind, and therefore none for UDP. It ignores `SIGHUP` (`external/caddy/sigtrap_posix.go:81-84` logs `"not implemented"`), sets no `SO_REUSEPORT` on its HTTP/3 UDP listeners, and has no mechanism for keeping a UDP flow attached to a draining process instance. Restarting Caddy terminates every live QUIC connection.
- caddy-rs behaviour: caddy-rs already serves HTTP/3 over UDP by default (`crates/server/Cargo.toml` enables the `http3` feature with `quinn`, `h3`, `h3-quinn`; `T-HTTP-030` and `T-HTTP-031` are done). In addition, and **opt-in**, caddy-rs can keep live QUIC flows across a binary restart by joining a `SO_REUSEPORT` group and dispatching packets with an eBPF `sk_reuseport` program supplied by the external `udpgrm` daemon, using udpgrm's socket-generation and working-generation model. This is the UDP counterpart to the TCP mechanism in `DIV-0155`: TCP inherits the listening socket file descriptor across `exec` (one kernel socket, nothing to orphan), while UDP has no listener to inherit and no accept queue, so it needs a reuseport group plus protocol-aware flow dispatch. caddy-rs never installs the eBPF hooks itself — `udpgrm --install --self` is privileged operator action with system-wide blast radius — and the server gains no new capabilities. When `udpgrm` is absent (the `getsockopt(UDP_GRM_WORKING_GEN)` probe fails `ENOPROTOOPT`), caddy-rs serves UDP normally and restarts with today's dropping behaviour, reporting the absence loudly and exactly once. The `DISSECTOR_FLOW` mode imposes a fixed cap on concurrent flows: **8192** (`MAX_TOTAL_FLOWS` in `cloudflare/udpgrm@e5bbb047d4899042505ddd15dce2aaf98369e778`, `ebpf/ebpf_internal.h:10`, asserted against `max_entries` at `:114`). That map is a `BPF_MAP_TYPE_LRU_HASH`, so the bound **evicts the least-recently-used flow rather than refusing a datagram** — the observable consequence of exceeding it is loss of restart stickiness for that flow, not an error. **Per-flow eviction is not observable from the client**, and no eviction counter is exported: `udpgrm`'s five client optnames carry no metrics or flow occupancy at the pinned commit, and its `metrics_map` and `lru_map` are reachable only by the daemon's own BPF program and privileged userspace helper, so an exact per-flow count would require either a new upstream optname or reading eBPF maps from the server, which `ADR-0045` §5 forbids. `ADR-0045` OQ-4 item 2 was amended on 2026-11-18 (`T-CORE-143`) to record this as the honest documented limit; the three documented conflict counters (`rx_flow_rg_conflict`, `tx_flow_update_conflict`, `rx_flow_new_bad_cookie`) are exported instead. An operator seeing a zeroed eviction counter would wrongly infer that no evictions occur, so none is presented. This is an extension and is deliberately **not** presented as parity, because Caddy has no equivalent. **Evidence status: unproven as of 2026-11-15** — the mechanism cannot be exercised in this program's sandbox (`udpgrm` absent, `UDP_GRM_*` absent from the kernel headers); see `docs/operations/evidence/2026-11-udpgrm-unprovable.txt`. No release note may describe this as working until `T-CORE-114` records a PROVEN verdict.
- Rationale: the adoption of QUIC made UDP graceful restart a real operational problem rather than a theoretical one, and caddy-rs already carries HTTP/3 traffic that a restart currently kills. The TCP technique does not transfer: there is no listener file descriptor to inherit and no accept queue, and a UDP flow is defined by the protocol rather than established by the kernel, so keeping flows sticky requires protocol-aware dispatch that only a reuseport eBPF program can provide. Building that in-process would mean shipping a privileged eBPF control plane inside the server, which is a far larger security surface than depending on an optional external daemon. Hence: integrate with udpgrm, never require it, never install hooks from the server, and degrade loudly where it is absent.
- Tracking: T-COMPAT-003
- Test: **UNPROVEN — read `docs/operations/evidence/2026-11-udpgrm-unprovable.txt` first (its own header records the run date, 2026-11-16).** (`docs/operations/evidence/udp-restart-verdict.txt` is the PROVEN/UNPROVEN verdict record owned by `T-CORE-114` and does not exist yet; until it does, the committed unprovability evidence is the authoritative artefact, not a verdict.) Only where an environment can host `udpgrm` is the assertion that a QUIC connection established before a restart continues to carry data across it recorded as PROVEN, together with that environment's kernel and `udpgrm` versions. In this program's sandbox the path is UNPROVEN and this entry says so rather than implying a passing test; the `udpgrm`-absent case asserts UDP keeps serving with a single loud log line; a socket registered to generation N+1 receives no new flows until the working generation is promoted; a conflicting `UDP_GRM_DISSECTOR` change against an existing reuseport group fails with a located `EPERM` error; and the flow-table cap is asserted and reported as a number.

## DIV-0157 — caddy-rs recommends `setcap cap_net_bind_service=+p` (permitted only) while Caddy's own CLI help still prints `=+ep`

- Status: open
- Area: Process lifecycle / listener binding (Linux capabilities)
- Caddy behaviour: Caddy v2.11.9 binds first and retries only when `listen()` fails with `EACCES` for a TCP/UDP address with a nonzero port, raising `CAP_NET_BIND_SERVICE` only if it is permitted but not effective, on a locked OS thread, lowering it again afterwards (`external/caddy/internal/bindcap_linux.go`, called from `external/caddy/listeners.go:182`). Its behaviour therefore works with the capability granted as permitted-only. **However Caddy's own CLI help text still prints the older advice** — `external/caddy/cmd/cobra.go:81` says `sudo setcap cap_net_bind_service=+ep $(which caddy)` — so Caddy ships two messages that disagree, and the code is the authoritative one.
- caddy-rs behaviour: **target behaviour, not yet implemented** (tracked by T-CORE-121..123; nothing is shipped as of 2026-11-15). When implemented it will match Caddy's runtime behaviour (bind unprivileged first, retry once on `EACCES` for a TCP/UDP nonzero-port bind, raise only when permitted-but-not-effective, lower via a drop guard on a thread that is never returned to a shared pool with the capability effective), and **deliberately documents `setcap cap_net_bind_service=+p` as the recommendation**, with the reason stated rather than just the command: with the effective bit set, the kernel refuses to execute the binary at all when the capability cannot be granted — containers run with `--cap-drop ALL`, or systemd units with an empty `CapabilityBoundingSet` — even when no privileged port is configured. No port-number threshold is used; the trigger is `EACCES` because whether the kernel requires the capability depends on `net.ipv4.ip_unprivileged_port_start`, which is often `0` in containers and can be above 1024. Unix sockets, abstract sockets and port 0 never touch capabilities. Linux-only; non-Linux keeps the plain bind path.
- Rationale: this is an availability fix, not a hardening preference. An operator who follows Caddy's printed `=+ep` advice and then tightens `CapabilityBoundingSet` or uses `--cap-drop ALL` finds the binary will not start at all, even with no privileged port in the configuration, and the failure is easy to misdiagnose because it happens before any of the operator's own configuration is read. Granting the capability as permitted-only keeps it dormant except for the microseconds of an actual privileged bind, which is also the smaller attack surface. The divergence is recorded because caddy-rs's documented recommendation differs from what the Caddy binary's help text prints, not because the runtime behaviour differs.
- Tracking: T-COMPAT-003
- Test: **unproven as of 2026-11-15** — no capability-configured environment exists in this program's sandbox, so these are the specification of what must be proven, not a record of passing tests. With the capability permitted-but-not-effective a privileged bind succeeds and the effective set is unchanged afterwards on every thread; with no capability the existing located `Error::bind` naming the configured address is returned unchanged; with the capability already effective no capability syscall is made; an unprivileged port and a unix socket and port 0 each assert zero `capget`/`capset` calls via a counter; a forced panic between raise and lower asserts the capability is not left effective; and non-Linux builds compile to the unchanged path.

## DIV-0158 — systemd fdstore pre-binding is a caddy-rs extension (TCP only for now)

- Status: open
- Area: Process lifecycle / listener binding (systemd integration)
- Caddy behaviour: Caddy has no fdstore pre-binding and no socket activation. It binds its own listeners, so binding a port below 1024 requires running as root, granting `CAP_NET_BIND_SERVICE` (`setcap` or `AmbientCapabilities=`), or using a systemd `.socket` unit. Caddy has no subcommand that binds listeners on behalf of the server and uploads them to systemd's File Descriptor Store.
- caddy-rs behaviour: **target behaviour, not yet implemented** (tracked by T-CORE-131..135; nothing is shipped as of 2026-11-15). An opt-in `listeners fdstore` mode lets a privileged `ExecStartPre=+` helper (`bind-fds`) derive the listener set from the same configuration the server will read, bind those listeners, upload them with `FDSTORE=1` and deterministic `FDNAME=`, and exit; the unprivileged server then adopts them through the **existing** socket-activation machinery (`crates/server/src/activation.rs`, already described in DIV-0040) instead of binding. A planned listener with no matching FD fails loudly rather than falling back to binding, so the server never silently re-acquires the privilege requirement. With the option off, behaviour is unchanged. **TCP only for now**: UDP listeners under fdstore mode fail loudly naming the missing prerequisite, because caddy-rs has no UDP socket activation at all (see DIV-0040, and ADR-0045 for why UDP restart needs `SO_REUSEPORT` + eBPF rather than an inherited listener). **QUIC flow preservation is UNPROVEN as of 2026-11-15**: a stored socket lets packets queue while the service is stopped instead of being refused, but whether that constitutes flow preservation has not been measured, and this mode must never be advertised as preserving QUIC connections.
- Rationale: this lets an operator serve privileged ports with `User=caddy`, no `setcap` and no `AmbientCapabilities=`, and keeps port numbers out of the unit file, so changing the configuration does not require touching systemd. It is registered as a divergence because Caddy offers no equivalent, and because it deliberately reuses the caddy-rs-only activation path from DIV-0040 rather than adding a second adoption mechanism. The design is safe only because the helper and the server derive listeners from one shared plan; a second source of truth would let a socket be uploaded under one identity and looked up under another. It does **not** preserve QUIC flows: uploading a bound UDP socket lets packets queue on the stored socket instead of being refused, which is not the same thing and must not be described as flow preservation (ADR-0045 §5 evidence discipline applies).
- Tracking: T-COMPAT-003
- Test: plan and FD-naming unit tests run anywhere; a mock notify socket proves `SCM_RIGHTS` upload, `FDNAME=` and `FDSTOREREMOVE=1`; the no-fallback and no-`$NOTIFY_SOCKET` error paths are unit-testable; the startup assertion that `CAP_NET_BIND_SERVICE` is absent from permitted, effective and ambient in fdstore mode is unit-testable. The end-to-end matrix (cold start, restart with the helper, restart without the helper, removed site freeing the port) requires a systemd container and is **unproven as of 2026-11-15** — it must not be described as passing until a named environment has run it.

## DIV-0159 — the pan-cross-transport drain/shutdown contract is undecided; no behaviour claim may be made until ADR-0048 is accepted

- Status: planned
- Area: Process lifecycle / graceful shutdown and restart, across every transport (TCP, UDP/QUIC, admin-API) and both programs (caddy-rs, caddy-rs-pm)
- Caddy behaviour: Caddy v2.11.9 has one shutdown path and no restart path: `SIGTERM`/`SIGINT` trigger a graceful shutdown bounded by `grace_period` and `shutdown_delay`, and `SIGHUP` is ignored as "not implemented", so there is no process-level restart and nothing to preserve across generations. Caddy attaches no observable "zero refused / zero dropped" guarantee to either path, and it has no UDP flow preservation at all.
- caddy-rs behaviour: **undecided — no behaviour may be claimed** (tracked by `T-CORE-140`; nothing is shipped as of 2026-11-15). `ADR-0048` proposes one drain primitive shared by `SIGTERM` shutdown and by restart, a bounded drain deadline, and the observability that proves zero refused and zero dropped connections across every transport and both programs. Until `ADR-0048`'s status is accepted, caddy-rs promises nothing about drain semantics, deadline bounds, refusal or drop counts, or which of the per-transport mechanisms in `DIV-0155`/`DIV-0156`/`DIV-0157`/`DIV-0158` actually compose. This entry exists so the contract has a registered identity before it has a shipped behaviour; it does not describe anything that exists.
- Rationale: the per-transport decisions (`ADR-0044` TCP restart, `ADR-0045` UDP/QUIC restart, `ADR-0046` capability parity, `ADR-0047` systemd fdstore) each fix one mechanism but none of them fixes the shared lifecycle, so the same drain primitive could otherwise be implemented twice with different deadlines and different observability, and "zero downtime" could be asserted for one transport while contradicting another. Registering the umbrella as a divergence rather than as parity is deliberate: Caddy has no restart path at all, so every preservation claim under this contract is a caddy-rs extension, and `ADR-0045` §5's evidence discipline applies to all of it — a stage that has not been measured on a named environment is unproven, by name, and must never be described as passing.
- Tracking: T-COMPAT-003
- Test: no test exists and none may be written against this behaviour until `ADR-0048` is accepted; `planctl.py check` lints this entry's structure only. What must be proven afterwards is the live-load zero-drop / zero-refusal matrix, run on a named environment per transport, with the measured counts committed as evidence rather than a pass flag.

## DIV-0160 — with `graceful-restart` enabled, a listener removed by a config reload keeps its port bound until the process exits

- Status: open
- Area: Process lifecycle / listener binding (config reload interacting with ecdysis fd inheritance)
- Caddy behaviour: Caddy has no listener-inheritance mechanism, so a config reload that removes a listener closes its socket and the port is released immediately; a connection to the old address is refused.
- caddy-rs behaviour: with the `graceful-restart` feature **disabled** (the default), behaviour is unchanged and identical to Caddy: the reloaded-away listener's port is released and connections are refused. With the feature **enabled**, `T-CORE-102` routes every TCP and admin/Unix listener through `ecdysis::build_listen_tcp`, and ecdysis 1.1.1 keeps a `F_DUPFD_CLOEXEC` copy of every registered socket for the whole life of the process. It exposes no way to release a single socket — `ListenerInfo::fd` is `pub(crate)`, the registry field is private, and only `Ecdysis::quit()` closes anything, which would close *every* socket and is therefore unusable in a running process. So when a reload removes a listener, caddy-rs drops it from the inheritance set (`ListenerBinder::forget`) and its accept loop ends, but the kernel socket stays open inside the registry: the port stays bound and accepts into a queue nobody serves. Nothing answers on it — the old route is gone — but the port is not free for another process until exit.
- Rationale: this is a real limitation of the adopted mechanism, not a choice, and it is registered rather than hidden because it is observable. `ADR-0044` §1 scopes graceful restart to replacing the *binary* and states explicitly that configuration reload is not in its scope, so reload semantics were never part of the design and the interaction was not considered when `T-CORE-102` was written. The affected invariant — "a reloaded-away listener stops serving" — still holds and is asserted in both configurations; what changes with the feature on is only "the port is released", which is weaker than the invariant and is why the test now asserts the stronger property. Landing the routing without recording this would have left an operator-visible difference (a removed site's port still appearing in `ss -lntp`) with no documentation and no owner. `T-CORE-141` owns the fix: either a vendored ecdysis patch that adds per-socket release, or a caddy-rs fd-registry layer that does not rely on ecdysis's internal dup.
- Tracking: T-COMPAT-003
- Test: `crates/server/tests/http_graceful_shutdown.rs::reload_honors_shutdown_delay_and_grace_for_closing_listeners` asserts, in both feature states, that a connection to the reloaded-away address is never answered by the old config's route; with the feature off it additionally asserts the connection is refused. `crates/server/tests/graceful_restart_inherit.rs` proves the registry records the bound address and that a registry-bound listener accepts. The port-release behaviour under the feature is **unproven as of 2026-11-16** and must not be described as working until `T-CORE-141` lands.

## DIV-0161 — the `geoip` global option and its `.mmdb` lookup are a caddy-rs extension with no Caddy equivalent
- Status: accepted
- Area: Compatibility / Radar
- Caddy behaviour: Caddy v2.11.9 has no `geoip` global option and no GeoIP provider seam. Its
  `@radar`-style ASN/country predicates do not exist, so there is no upstream option, no upstream
  JSON key and no upstream lookup behaviour to match; a Caddyfile using `geoip` is a parse error.
- caddy-rs behaviour: the global option `geoip <provider> <path>` configures a local MaxMind-format
  database, where `<provider>` is `dbip` or `maxmind` and `<path>` is the `.mmdb` file. The option is
  **repeatable** because ASN and country records live in separate database files: one line for the
  ASN database and one for the country database, either of which may be omitted. The adapter emits
  the option as a JSON array of `{"provider", "path"}` objects in the order written, and leaves the
  path verbatim rather than resolving it against the Caddyfile's directory. `caddy_rs_http::geoip`
  provides the reader: `MmdbGeoIp` implements the existing `GeoIpProvider` trait over one or both
  databases, resolving an address to `GeoLocation { asn, country }` with the country upper-cased as
  ISO 3166-1 alpha-2. Lookups are fail-open: a **missing** database file is skipped with a warning
  naming the full path and the caller installs `NoopGeoIp`, so the server keeps serving; a file that
  exists but cannot be opened or is not a valid database is a located error, because that is a real
  misconfiguration and silently degrading would hide it. `select_provider` turns the configured
  entries into the `Arc<dyn GeoIpProvider>` the matcher takes, with no entries selecting `NoopGeoIp`
  silently (nothing configured is the default, not a mistake) and unusable entries selecting it with
  warnings. Under `stock_compat true` the option is rejected as an unsupported caddy-rs extension
  with a located error naming the line, the same treatment as `radar` and `trust_cdn`.
- Rationale: threat-intelligence predicates keyed on ASN and country are only useful if the server
  can actually resolve them, and the alternative to a local database is either a per-request API call
  (latency, availability and privacy cost on the request path) or no lookup at all. DB-IP is the
  documented default because it needs no license key, and a credential that must be obtained before
  anything works is the most likely reason a deployment would quietly ship without a database.
  Failing open on a missing file rather than refusing to start is deliberate: GeoIP enriches a
  security predicate, and turning a missing optional database into an outage would trade a partial
  loss for a total one. Distinguishing "absent" from "present but unreadable" keeps the honest case
  quiet while still catching a typo or a corrupt file. The option is registered as a divergence
  because every part of it — the option name, its repeatability, the JSON key, the provider words
  and the fail-open policy — is absent from Caddy v2.11.9.
- Tracking: T-COMPAT-003
- Test: `crates/http/tests/geoip.rs` (`resolves_asn_and_country_for_a_known_address` proves a real
  database resolves ASN 29518 and country SE for `89.160.20.112` against the committed MaxMind test
  fixtures, `an_unknown_address_resolves_to_none` covers the unknown-address case,
  `resolves_asn_when_only_the_asn_database_is_configured` and
  `resolves_country_when_only_the_country_database_is_configured` cover partial configuration,
  `no_database_configured_falls_back_to_noop_and_never_panics` covers the fail-open fallback,
  `a_missing_optional_database_warns_once_naming_the_path` proves the warning names the path,
  `counters_distinguish_lookups_hits_and_misses` covers the counters, and
  `configured_entries_select_a_real_provider_that_resolves` plus
  `selection_classifies_asn_and_country_paths_by_name` cover `select_provider`);
  `crates/config/tests/geoip.rs` (`a_single_geoip_line_emits_one_entry`,
  `the_option_is_repeatable_and_preserves_written_order`,
  `the_path_is_emitted_verbatim_without_resolution`,
  `an_unknown_provider_is_a_located_error_listing_the_accepted_words`,
  `a_missing_argument_is_a_located_error`, `stock_compat_rejects_geoip` and
  `stock_compat_rejects_radar_and_geoip_together`). **Limit:** the provider is not yet reachable
  from a production request path — `@radar` is unregistered and no non-test code constructs
  `RadarMatcher`, as recorded by DIV-0149. Registering it is T-ROUTE-063; until that lands, this
  option configures a provider that only tests and future wiring consume, and the end-to-end
  "a request matched on ASN in a running server" claim must not be made.

## DIV-0162 — `apps.layer4` is a caddy-l4 extension app, named positionally and carrying no registered module
- Status: accepted
- Area: Compatibility / layer4
- Caddy behaviour: stock Caddy v2.11.9 has no `layer4` app, no `layer4 { }` global option and no
  stream handlers or matchers of any kind. `layer4` is a third-party plugin (`caddy-l4`), so there
  is no upstream `caddy adapt` oracle for it and a stock Caddyfile using it is a parse error.
- caddy-rs behaviour: the global `layer4 { <listen> { ... } }` option adapts to
  `apps.layer4.servers.<key>.{listen, routes}`. Three properties differ from what a reader of the
  ADRs might assume. (1) **Server keys are positional** (`srv0`, `srv1`, ... in listener order), not
  derived from the listen address: ADR-030's example sketched `l4-443-tcp`/`l4-443-udp` and
  ADR-031's sketched `l4-443`/`l4-udp-51820`, so the ADRs and the code disagreed three ways. The key
  is a map key with no runtime meaning; positional naming keeps the adapted JSON independent of the
  address, so inserting a listener ahead of another does not rename the rest. Both ADRs now show the
  shipped form. (2) **`layer4` is carried in `apps.extra`, not as a typed app.** The core model
  registers only `http`, `tls` and `pki`, so `validate_config` rejects an adapted config containing
  `apps.layer4` with "unknown app module(s): layer4". This is the same position `radar` occupies
  until its runtime row lands, and it is why the `layer4_full_*` fixtures cannot live in
  `tests/fixtures/local/` (that harness also requires core validation) and live in
  `tests/fixtures/layer4/` with their own test instead. (3) **UDP listeners normalise to one
  spelling.** `caddy-l4` accepts `host:port/udp`, `udp/host:port` and `udp:host:port`; all three
  emit the single canonical `listen` element `host:port/udp`, so the adapted JSON does not depend on
  the spelling the operator chose.
- Rationale: `layer4` is a real, widely used extension and the project's ADR-030/ADR-031 commit to
  it, but it is a plugin, so every part of this surface — the option name, the app key, the handler
  and matcher vocabulary, the UDP spellings and the server naming — is absent from Caddy v2.11.9 and
  must be registered rather than assumed to match. Recording the three properties explicitly is
  what stops the next agent from "fixing" the server keys to match an ADR example, or from moving
  the fixtures into `local/` and finding the harness permanently red.
- Tracking: T-COMPAT-003
- Test: `crates/config/tests/layer4_full_adapt.rs` (`layer4_full_fixtures_adapt_exactly` pins the
  whole corpus byte for byte, `every_layer4_server_declares_its_listen_address` asserts each server
  carries a ported listen element, `udp_listeners_are_emitted_in_the_canonical_form` proves all three
  UDP spellings and that a TCP listener is not mistaken for one);
  `crates/config/src/layer4.rs` module tests (`adr_031_example_adapts_in_full`,
  `inline_tls_block_defaults_mode_and_rejects_unknown_options`,
  `throttle_emits_the_runtime_rate_limit_field_names`, `udp_listener_adapts_and_normalises_every_spelling`,
  `a_tcp_listener_is_not_mistaken_for_udp`). **Limit:** the adapter carries the configuration; the
  runtime `layer4` app is not registered, so an adapted config with `apps.layer4` does not load and
  no end-to-end stream routing is claimed here.

## DIV-0163 — Pre-1970 OCSP timestamps are rejected, not represented
- Status: accepted
- Area: TLS
- Caddy behaviour: OCSP response parsing delegates to `golang.org/x/crypto/ocsp`, whose ASN.1 time decoding goes through `encoding/asn1` into `time.Time`. `time.Time` is signed, so a `thisUpdate`/`nextUpdate` before 1970 (for example a UTCTime `500101000000Z`, which denotes 1950-01-01 because `YY >= 50` means `19YY`) decodes to a negative instant and the response is accepted.
- caddy-rs behaviour: `parse_asn1_time` returns a typed `OcspError::Malformed` ("ASN.1 time ... is before the Unix epoch and cannot be represented") for any instant before 1970-01-01. The stapled-response representation is `SystemTime`, which is unsigned, so those instants have no representation. Before T-TLS-103 the value was not rejected but silently corrupted: the civil day count was cast to `u64`, wrapped to ~1.8e19, and the seconds multiplication overflowed, panicking in debug builds and yielding a nonsense timestamp in release.
- Rationale: rejecting is the honest outcome. Clamping to the epoch would turn "unrepresentable" into "1970-01-01" and change the meaning of the freshness comparison in `staple_for_certificate`, which compares `next_update` against `this_update`. An OCSP responder emitting a pre-1970 timestamp is already signalling a broken clock, so refusing the response is safer than acting on a fabricated one. Both outcomes leave the staple unusable; the difference is that caddy-rs now says why.
- Tracking: T-COMPAT-003
- Test: `crates/tls/tests/ocsp_fuzz.rs` (`pre_epoch_next_update_is_rejected_not_panicking`, `pre_epoch_this_update_is_rejected_not_panicking`, `epoch_and_later_next_update_still_parses`).
## DIV-0164 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.combined not implemented - caddy-rs cannot combine multiple CA certificate sources into a single pool
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.combined; operator must use explicit source or inline certificates
- Rationale: Combined CA pool source is needed for operators managing multiple certificate authorities; missing forces manual configuration and reduces automation usability
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs combined_source_test

## DIV-0165 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.file not implemented - caddy-rs cannot load CA certificates from file paths
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.file; operator must use inline certificates or other sources
- Rationale: File-based CA pool source is a common deployment pattern; missing creates friction for file-based certificate management
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs file_source_test

## DIV-0166 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.http not implemented - caddy-rs cannot fetch CA certificates via HTTP
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.http; operator must use file or inline certificates
- Rationale: HTTP CA pool source enables automated certificate retrieval; missing limits automated deployment options
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs http_source_test

## DIV-0167 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.inline not implemented - caddy-rs cannot use inline CA certificates
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.inline; operator must use file-based sources
- Rationale: Inline CA certificates are useful for embedded deployments and testing; missing limits caddy-rs flexibility
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs inline_source_test

## DIV-0168 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.pki_intermediate not implemented - caddy-rs cannot load intermediate PKI CA certificates
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.pki_intermediate; operator must concatenate intermediates manually
- Rationale: Intermediate CA support is essential for proper certificate chain validation; missing could cause TLS handshake failures
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs intermediate_source_test

## DIV-0169 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.pki_root not implemented - caddy-rs cannot load root PKI CA certificates
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.pki_root; operator must use file-based sources
- Rationale: Root CA support is fundamental to TLS; missing is a security gap as root certificates validate the entire chain
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs root_source_test

## DIV-0170 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.storage not implemented - caddy-rs cannot use storage-based CA pools
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.storage; operator must use explicit certificate sources
- Rationale: Storage-based CA pools enable persistent certificate management across reloads; missing limits deployment flexibility
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs storage_source_test

## DIV-0171 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.ca_pool.source.system not implemented - caddy-rs cannot use system CA certificates
- caddy-rs behaviour: caddy-rs missing tls.ca_pool.source.system; operator must explicitly trust only configured CAs
- Rationale: System CA integration is important for interoperability with OS trust stores; missing may break compatibility with some infrastructure
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/ca_pool_test.rs system_source_test

## DIV-0172 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.client_auth.verifier.dummy not implemented - caddy-rs cannot use dummy client auth verifier
- caddy-rs behaviour: caddy-rs missing tls.client_auth.verifier.dummy; client certificate verification requires explicit verifier
- Rationale: Test/dummy verifiers are needed for development and testing; missing limits caddy-rs testability
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/client_auth_test.rs dummy_verifier_test

## DIV-0173 — TLS
- Status: open
- Area: TLS
- Caddy behaviour: tls.client_auth.verifier.leaf not implemented - caddy-rs cannot verify client certificates against leaf CA
- caddy-rs behaviour: caddy-rs missing tls.client_auth.verifier.leaf; client cert verification requires explicit verifier configuration
- Rationale: Leaf CA verifier is a common client auth pattern; missing limits caddy-rs client TLS deployment options
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/client_auth_test.rs leaf_verifier_test

## DIV-0174 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.copy_response not implemented - caddy-rs cannot copy response from upstream
- caddy-rs behaviour: caddy-rs missing http.handlers.copy_response; reverse_proxy responses cannot be transformed via copy
- Rationale: Copy response handler is essential for response manipulation workflows; missing limits caddy-rs flexibility in reverse proxy use cases
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/copy_response_test.rs

## DIV-0175 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.copy_response_headers not implemented - caddy-rs cannot copy response headers from upstream
- caddy-rs behaviour: caddy-rs missing http.handlers.copy_response_headers; reverse_proxy cannot copy upstream headers
- Rationale: Header copying is a common pattern for propagating upstream metadata; missing creates friction for header manipulation
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/copy_headers_test.rs

## DIV-0176 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.intercept not implemented - caddy-rs cannot intercept and modify requests/responses
- caddy-rs behaviour: caddy-rs missing http.handlers.intercept; no request/response interception capability
- Rationale: Intercept handler is fundamental for request/response transformation; without it, caddy-rs cannot support many middleware patterns
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/intercept_test.rs

## DIV-0177 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.invoke not implemented - caddy-rs cannot invoke subroutines/handlers inline
- caddy-rs behaviour: caddy-rs missing http.handlers.invoke; no inline handler invocation
- Rationale: Invoke handler enables handler composition and reuse; missing limits caddy-rs modularity
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/invoke_test.rs

## DIV-0178 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.log_append not implemented - caddy-rs cannot append to logs
- caddy-rs behaviour: caddy-rs missing http.handlers.log_append; no structured log appending
- Rationale: Log append is needed for structured logging and audit trails; missing limits observability
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/log_append_test.rs

## DIV-0179 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.not not implemented - caddy-rs cannot mark requests for special handling
- caddy-rs behaviour: caddy-rs missing http.handlers.not; no requestNot handler
- Rationale: Not handler is used for request filtering and routing decisions; missing impacts routing flexibility
- Tracking: T-COMPAT-003
- Test: crates/router/tests/not_handler_test.rs

## DIV-0180 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.response_code not implemented - caddy-rs cannot set custom response codes
- caddy-rs behaviour: caddy-rs missing http.handlers.response_code; no response code manipulation
- Rationale: Response code manipulation is essential for API gateway use cases; missing limits caddy-rs flexibility
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/response_code_test.rs

## DIV-0181 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.set_response_headers not implemented - caddy-rs cannot set response headers
- caddy-rs behaviour: caddy-rs missing http.handlers.set_response_headers; no response header setting
- Rationale: Setting response headers is a basic reverse proxy requirement; missing creates significant friction
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/set_headers_test.rs

## DIV-0182 — HTTP handlers
- Status: open
- Area: HTTP handlers
- Caddy behaviour: http.handlers.template not implemented - caddy-rs cannot use template-based responses
- caddy-rs behaviour: caddy-rs missing http.handlers.template; no template rendering for responses
- Rationale: Template handler enables dynamic response generation; missing limits caddy-rs dynamic content capabilities
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/template_test.rs

## DIV-0183 — HTTP matchers
- Status: open
- Area: HTTP matchers
- Caddy behaviour: http.matchers.header_regexp not implemented - caddy-rs cannot match headers with regex
- caddy-rs behaviour: caddy-rs missing http.matchers.header_regexp; header matching limited to literal/prefix only
- Rationale: Regex header matching is a powerful pattern for complex routing; missing limits caddy-rs routing expressiveness
- Tracking: T-COMPAT-003
- Test: crates/http/tests/matcher_test.rs header_regexp_test

## DIV-0184 — HTTP matchers
- Status: open
- Area: HTTP matchers
- Caddy behaviour: http.matchers.not not implemented - caddy-rs cannot negate matcher results
- caddy-rs behaviour: caddy-rs missing http.matchers.not; no negation of matcher conditions
- Rationale: Negation is essential for complex routing policies (e.g., 'match if NOT X')
- Tracking: T-COMPAT-003
- Test: crates/http/tests/matcher_test.rs not_matcher_test

## DIV-0185 — HTTP matchers
- Status: open
- Area: HTTP matchers
- Caddy behaviour: http.matchers.url_pattern not implemented - caddy-rs cannot match URLs with patterns
- caddy-rs behaviour: caddy-rs missing http.matchers.url_pattern; URL matching limited to exact/prefix only
- Rationale: URL pattern matching is a common routing need; missing limits caddy-rs routing capabilities
- Tracking: T-COMPAT-003
- Test: crates/http/tests/matcher_test.rs url_pattern_test

## DIV-0186 — HTTP matchers
- Status: open
- Area: HTTP matchers
- Caddy behaviour: http.matchers.vars not implemented - caddy-rs cannot match against request variables
- caddy-rs behaviour: caddy-rs missing http.matchers.vars; variable-based matching not supported
- Rationale: Variable matching enables dynamic routing based on request attributes; missing limits caddy-rs flexibility
- Tracking: T-COMPAT-003
- Test: crates/http/tests/matcher_test.rs vars_matcher_test

## DIV-0187 — HTTP matchers
- Status: open
- Area: HTTP matchers
- Caddy behaviour: http.matchers.vars_regexp not implemented - caddy-rs cannot match vars with regex
- caddy-rs behaviour: caddy-rs missing http.matchers.vars_regexp; regex variable matching not supported
- Rationale: Regex variable matching extends variable-based routing; missing limits expressiveness
- Tracking: T-COMPAT-003
- Test: crates/http/tests/matcher_test.rs vars_regexp_test

## DIV-0188 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.cookie not implemented - caddy-rs cannot filter log entries by cookie
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.cookie; no cookie-based log filtering
- Rationale: Cookie filtering in logs is important for privacy and security (preventing PII in logs); missing could leak sensitive data
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs cookie_filter_test

## DIV-0189 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.delete not implemented - caddy-rs cannot delete log entries
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.delete; no log entry deletion
- Rationale: Log entry deletion is needed for GDPR compliance and sensitive data removal; missing limits compliance capabilities
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs delete_filter_test

## DIV-0190 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.hash not implemented - caddy-rs cannot hash log entries
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.hash; no log entry hashing
- Rationale: Log hashing is needed for privacy-preserving logging and deduplication; missing limits observability options
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs hash_filter_test

## DIV-0191 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.ip_mask not implemented - caddy-rs cannot mask IP addresses in logs
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.ip_mask; no IP masking in logs
- Rationale: IP masking is critical for privacy and compliance (GDPR, etc.); missing could leak sensitive network information
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs ip_mask_filter_test

## DIV-0192 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.multi_regexp not implemented - caddy-rs cannot filter with multiple regex
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.multi_regexp; no multi-regex log filtering
- Rationale: Multiple regex filtering enables complex log manipulation; missing limits observability flexibility
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs multi_regexp_filter_test

## DIV-0193 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.not not implemented - caddy-rs cannot negate filter results
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.not; no negation of filter conditions
- Rationale: Filter negation is needed for complex log manipulation policies; missing limits flexibility
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs not_filter_test

## DIV-0194 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.regexp not implemented - caddy-rs cannot match log entries with regex
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.regexp; no regex-based log filtering
- Rationale: Regex log filtering is a common pattern for targeted log manipulation; missing limits observability
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs regexp_filter_test

## DIV-0195 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.replace not implemented - caddy-rs cannot replace text in log entries
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.replace; no text replacement in logs
- Rationale: Log text replacement is needed for data anonymization and transformation; missing limits compliance capabilities
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs replace_filter_test

## DIV-0196 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.regexp_case not implemented - caddy-rs cannot do case-insensitive regex filtering
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.regexp_case; case-insensitive regex filtering not supported
- Rationale: Case-insensitive regex filtering is important for robust log manipulation; missing limits flexibility
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs regexp_case_filter_test

## DIV-0197 — Logging
- Status: open
- Area: Logging
- Caddy behaviour: caddy.logging.encoders.filter.trim not implemented - caddy-rs cannot trim log entries
- caddy-rs behaviour: caddy-rs missing caddy.logging.encoders.filter.trim; no log entry trimming
- Rationale: Log trimming is needed for size management and focused logging; missing limits observability options
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/logging_test.rs trim_filter_test

## DIV-0198 — JSON top-level
- Status: open
- Area: JSON top-level
- Caddy behaviour: apps.tls.certificates.pkcs11 not implemented - caddy-rs cannot use PKCS#11 certificate tokens
- caddy-rs behaviour: caddy-rs missing apps.tls.certificates.pkcs11; no PKCS#11 certificate integration
- Rationale: PKCS#11 is essential for hardware security module (HSM) integration in production deployments; missing is a significant security gap for HSM-dependent environments
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/pkcs11_test.rs

## DIV-0199 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: caddy.storage not fully implemented - caddy-rs storage backend limited
- caddy-rs behaviour: caddy-rs missing caddy.storage test_blocking; limited storage backend support
- Rationale: Storage backend flexibility is needed for diverse deployment architectures; missing limits deployment options
- Tracking: T-COMPAT-003
- Test: crates/storage/tests/storage_test.rs

## DIV-0200 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-encoder http.encoders.gzip not fully implemented - caddy-rs gzip encoder differences from klauspost
- caddy-rs behaviour: caddy-rs missing http.encoders.gzip; uses flate2 instead of klauspost gzip; decompression semantics identical but Content-Length may differ
- Rationale: Gzip encoder differences can cause Content-Length mismatches; decompressed content is compatible but header semantics may differ; operator should verify
- Tracking: T-COMPAT-003
- Test: crates/http/tests/encode_test.rs gzip_test

## DIV-0201 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-encoder http.encoders.zstd not fully implemented - caddy-rs zstd encoder differences from klauspost
- caddy-rs behaviour: caddy-rs missing http.encoders.zstd; uses zstd crate instead of klauspost; checksum presence may differ from Caddy's default
- Rationale: Zstd encoder byte differences can affect Content-Length; decompressed content is compatible but operators should verify
- Tracking: T-COMPAT-003
- Test: crates/http/tests/encode_test.rs zstd_test

## DIV-0202 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-handler http.handlers.copy_response_headers not wired - caddy-rs handler not connected to router
- caddy-rs behaviour: caddy-rs http.handlers.copy_response_headers registered but not invoked in request pipeline
- Rationale: Handler existence without pipeline integration means configuration is accepted but non-functional; should either wire or reject with located error
- Tracking: T-COMPAT-003
- Test: crates/proxy/tests/handler_integration_test.rs

## DIV-0203 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.tls 24 total missing features - see DIV-0164 to DIV-0173 for individual entries
- caddy-rs behaviour: caddy-rs missing 24 TLS features across ca_pool sources and client_auth verifiers
- Rationale: 24 TLS features missing represents a significant gap for HTTPS deployment; prioritized for implementation
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/comprehensive_tls_test.rs

## DIV-0204 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.logging 11 missing filter types - see DIV-0188 to DIV-0197 for individual entries
- caddy-rs behaviour: caddy-rs missing 11 logging filter types; basic log manipulation capabilities absent
- Rationale: 11 missing logging filters limits observability and compliance capabilities; important for production deployments
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/comprehensive_logging_test.rs

## DIV-0205 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.admin-api 6 missing admin API surfaces - load, metrics, mock, mock_provision, pki and 1 more
- caddy-rs behaviour: caddy-rs missing admin.api.load, admin.api.metrics, admin.api.mock, admin.api.mock_provision, admin.api.pki and another surface
- Rationale: Admin API surface gaps limit caddy-rs management capabilities; operators cannot fully manage running instances via API
- Tracking: T-COMPAT-003
- Test: crates/admin/tests/admin_api_test.rs

## DIV-0206 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.dns-provider dns.providers.mock not implemented - caddy-rs cannot use mock DNS provider
- caddy-rs behaviour: caddy-rs missing dns.providers.mock; no mock DNS provider for testing
- Rationale: Mock DNS provider is essential for testing ACME/DNS-01 challenges without external services; missing limits testing capabilities
- Tracking: T-COMPAT-003
- Test: crates/tls/tests/dns_mock_test.rs

## DIV-0207 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.filesystems caddy.filesystems not fully implemented - caddy-rs filesystem support limited
- caddy-rs behaviour: caddy-rs missing caddy.filesystems; limited filesystem backend support compared to Caddy
- Rationale: Filesystem support diversity is needed for different deployment environments; missing limits deployment flexibility
- Tracking: T-COMPAT-003
- Test: crates/config/tests/filesystem_test.rs

## DIV-0208 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.config-loaders caddy.config_loaders.http not implemented - caddy-rs HTTP config loader missing
- caddy-rs behaviour: caddy-rs missing caddy.config_loaders.http; no HTTP-based configuration loading
- Rationale: HTTP config loader enables remote/configuration-from-URL patterns; missing limits caddy-rs flexibility for dynamic config
- Tracking: T-COMPAT-003
- Test: crates/config/tests/http_config_loader_test.rs

## DIV-0209 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.storage caddy.storage.test_blocking not implemented - caddy-rs blocking storage test missing
- caddy-rs behaviour: caddy-rs missing caddy.storage.test_blocking; no blocking storage test capability
- Rationale: Blocking storage test is needed for performance and concurrency testing; missing limits testing capabilities
- Tracking: T-COMPAT-003
- Test: crates/storage/tests/blocking_test.rs

## DIV-0210 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.other caddy.network_proxy.none not implemented - caddy-rs network proxy support limited
- caddy-rs behaviour: caddy-rs missing caddy.network_proxy.none; no network proxy none configuration
- Rationale: Network proxy none support is needed for specific deployment patterns; missing limits configuration options
- Tracking: T-COMPAT-003
- Test: crates/config/tests/network_proxy_test.rs

## DIV-0211 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.other events not implemented - caddy-rs event handling limited
- caddy-rs behaviour: caddy-rs missing events; no event handling capability
- Rationale: Event handling is needed for extension protocols and lifecycle management; missing limits caddy-rs extensibility
- Tracking: T-COMPAT-003
- Test: crates/pm/tests/event_test.rs

## DIV-0212 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.other pki not fully implemented - caddy-rs PKI support limited
- caddy-rs behaviour: caddy-rs missing pki; limited PKI backend support compared to Caddy
- Rationale: PKI backend diversity is needed for different certificate management systems; missing limits deployment flexibility
- Tracking: T-COMPAT-003
- Test: crates/pki/tests/pki_test.rs

## DIV-0213 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-other http.authentication.hashes.argon2id not implemented - caddy-rs cannot use Argon2id password hashing
- caddy-rs behaviour: caddy-rs missing http.authentication.hashes.argon2id; no Argon2id password hash support
- Rationale: Argon2id is the recommended password hashing algorithm; missing is a security concern as weaker hashes may be used by default
- Tracking: T-COMPAT-003
- Test: crates/http/tests/auth_test.rs argon2id_test

## DIV-0214 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-other http.authentication.hashes.bcrypt not implemented - caddy-rs cannot use bcrypt password hashing
- caddy-rs behaviour: caddy-rs missing http.authentication.hashes.bcrypt; no bcrypt password hash support
- Rationale: Bcrypt is a widely-used password hashing algorithm; missing limits compatibility with existing password databases
- Tracking: T-COMPAT-003
- Test: crates/http/tests/auth_test.rs bcrypt_test

## DIV-0215 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-other http.authentication.providers.http_basic not implemented - caddy-rs cannot use HTTP basic auth provider
- caddy-rs behaviour: caddy-rs missing http.authentication.providers.http_basic; no HTTP basic auth provider
- Rationale: HTTP basic auth provider is a common authentication method; missing limits caddy-rs authentication capabilities
- Tracking: T-COMPAT-003
- Test: crates/http/tests/auth_test.rs http_basic_test

## DIV-0216 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-other http.ip_sources.static not implemented - caddy-rs cannot configure static IP sources
- caddy-rs behaviour: caddy-rs missing http.ip_sources.static; no static IP source configuration
- Rationale: IP source configuration is needed for access control and rate limiting; missing limits security deployment options
- Tracking: T-COMPAT-003
- Test: crates/http/tests/ip_source_test.rs

## DIV-0217 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.http-other http.precompressed.br not implemented - caddy-rs cannot use brotli precompression
- caddy-rs behaviour: caddy-rs missing http.precompressed.br; no brotli precompression support
- Rationale: Brotli precompression is needed for optimal compression; missing limits response optimization capabilities
- Tracking: T-COMPAT-003
- Test: crates/http/tests/precompressed_test.rs brotli_test

## DIV-0218 — Module parity
- Status: open
- Area: Module parity
- Caddy behaviour: module.other {env.CADDY_TEST_EAB_KEY_ID} not implemented - caddy-rs environment variable handling limited
- caddy-rs behaviour: caddy-rs missing {env.CADDY_TEST_EAB_KEY_ID}; environment variable placeholders not fully supported
- Rationale: Environment variable placeholders are essential for configuration flexibility and secret management; missing limits caddy-rs configurability
- Tracking: T-COMPAT-003
- Test: crates/config/tests/env_var_test.rs eab_key_id_test

## DIV-0219 — Runtime
- Status: open
- Area: Runtime
- Caddy behaviour: graceful connection draining with grace period not implemented - caddy-rs cannot drain connections with grace period
- caddy-rs behaviour: caddy-rs missing graceful connection draining with grace period; no connection draining support
- Rationale: Graceful connection draining is essential for zero-downtime reloads and deployments; missing creates risk of connection reset during updates
- Tracking: T-COMPAT-003
- Test: crates/runtime/tests/draining_test.rs

