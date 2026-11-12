# caddy-rs proxy manager — foundation workspace

This is the proxy-manager foundation workspace. It is deliberately independent of the
`caddy-rs` workspace and of the NPM compatibility adapter.

| Crate | Role |
|---|---|
| `caddy-rs-pm-state` | Backend-agnostic durable document state: snapshots, revisions, CAS transactions, one serialized writer. No SQL, C or network dependency. |
| `caddy-rs-pm-core` | Certificate and host domain model: certificate origins/policies, host TLS binding, proxy/redirect/dead host validation, domain uniqueness. |
| `caddy-rs-pm-compiler` | Deterministic Caddy JSON route compiler for proxy/redirect/dead hosts; emits HTTP and HTTPS route lists, HSTS and forced-SSL redirects. No listeners, TLS automation or key material. |
| `caddy-rs-pm-config` | Deterministic Caddy JSON assembler: route-only `assemble`/`assemble_from_hosts`, policy-aware `assemble_with_tls` with `apps.tls` automation, and `assemble_with_tls_and_certificates` with `load_files` + tagged `tls_connection_policies` for stored manual certificates. No logging, access lists or admin apply. |
| `caddy-rs-pm-hosts` | Durable host repository over `pm-state`: get/list/create/update/delete with CAS revisions, atomic domain-index uniqueness, next-id reservation, and memory/snapshot backend tests. |
| `caddy-rs-pm-service` | Application service over `pm-hosts`: id-allocating create, CAS update/delete, list, route compilation, and TLS binding validation against auto policies and manual certificate metadata. No REST API, UI or auth. |
| `caddy-rs-pm-policies` | Durable auto-certificate policy repository over `pm-state`: get/list/create/update/delete with CAS revisions, tombstones, monotonic id reservation and host coverage validation against `pm-core` hosts. |
| `caddy-rs-pm-import` | Native-first NPM v2.16 host-payload import mapping: proxy/redirect/dead hosts to `pm-core`, explicit certificate origins, located errors for unsupported payload features and warnings for flags without a native implementation. |
| `caddy-rs-pm-runtime` | PM composition root: data-directory preflight (`0700`, writability probe), `<data_dir>/pm` state layout (including `pm/secrets`), legacy Caddy detection (warning only), host/policy/certificate/service wiring, and the loopback-only config apply pipeline (stage/diff/load/verify/record). |
| `caddy-rs-pm-certificates` | Manual certificate validation and secret store: strict PEM chain/key parsing, key-match proof, expiry/SAN checks, `0600` key files in a `0700` directory, monotonic ids/tombstones, metadata-only state and no key bytes in responses. |
| `caddy-rs-pm-api` | Native REST API with axum: `/api/v1` router, host CRUD/enable/disable with strong per-host ETags and `If-Match` CAS, certificate intents with inventory-derived status, manual certificate upload/list/delete, config apply/revision history, list filters/pagination, health/setup/version/config, typed error envelope, loopback-only mutation guard, request ID and logging middleware. |

## Why a nested workspace

`caddy-rs` core must remain database-free and must not depend on a management product. The PM will
grow its own API/UI/certificate service; keeping its crates in `pm/` prevents accidental imports
from `crates/http`, `crates/proxy` or `crates/tls`. The data plane cannot compile against this
workspace.

## `pm-state`

The store is a namespaced document store, not a relational database:

- `u64` revision per document; `u64` generation per store;
- immutable `Snapshot` reads (`Arc`), so readers do not wait for the writer;
- one `Mutex`-serialized writer per store; no reader/writer lock contention;
- compare-and-swap preconditions (`check_revision`, `check_missing`); a transaction without a check is an unconditional upsert, so callers that need CAS must add the check
- atomic transactions: a failed precondition or persistence error leaves the store unchanged;
- `backup()` writes a consistent JSON export.

Backends in this slice:

- `MemoryStore` — tests and ephemeral use;
- `SnapshotStore` — full JSON snapshot, temp file + `fsync` + atomic rename, `0600` file mode.

The snapshot backend is intentionally a **single-node, modest-scale** backend. It does not implement
multi-process locking or a write-ahead log. A future `redb` or external-SQL backend implements the
same `StateStore` trait without changing any consumer. Per the design decision in the research, a
database driver is **not** built into caddy-rs core, and WASM is not used for database I/O.

## `pm-core`

The certificate model separates the classes that must never be conflated:

| Origin | Display | Binding | Private key |
|---|---|---|---|
| `auto_generated` | Auto-generated | auto policy id | never enters the PM |
| `manual` | Manual | certificate id | PM secret store |
| `acme_configured` | ACME (configured) | certificate id | never enters the PM |
| `internal_ca` | Internal CA | certificate id | never enters the PM |

`AutoCertificatePolicy` owns subjects/wildcards, `on_demand` vs `eager` mode, issuer, key type,
renewal ratio and the ACME challenge (`http01`, `tls-alpn01` or `dns01`, default `http01`). Core
on-demand TLS is not implemented, so the default policy mode is `eager`. Validation rejects a
wildcard subject with HTTP-01/TLS-ALPN-01 (public ACME only issues wildcards via DNS-01); an
`internal` issuer is exempt because it runs no ACME challenge. `HostTls` requires exactly one mode
and validates subject coverage before a host is saved. An auto-generated certificate cannot be selected by id; a manual/ACME certificate cannot be
attached to an auto policy.

The certificate types contain **no private-key bytes**. Manual key material belongs in a separate
secret store; auto/ACME keys stay in core certificate storage.

## `pm-core` host model

`Host` is the managed HTTP host: stable id, normalized domains, one `HostTls` binding and exactly
one spec (`Proxy`, `Redirect`, `Dead`). Validation is split so the compiler and API can use it
without loading every certificate:

- `validate_structure` — ids, domains, TLS mode/reference consistency, HSTS/forced-SSL invariants and
  kind-specific fields (upstream scheme/host/port, redirect status/target, dead host);
- `validate` — additionally checks the referenced certificate/policy and domain coverage;
- `validate_host_domain_uniqueness` and `validate_host_id_uniqueness` — reject a domain or id claimed
  by two hosts.

## `pm-compiler`

`compile_routes(&[Host])` returns ordered `http` and `https` route lists:

- proxy → `reverse_proxy` with a `dial` address (`host:port`, IPv6 bracketed); HTTPS upstreams get a
  TLS `transport`; `preserve_host=false` rewrites upstream `Host`;
- redirect → `static_response` with a `Location` placeholder, `Auto` scheme, optional path preserve;
- dead → 404;
- TLS-enabled hosts get an HTTPS route; `ssl_forced` adds a 301 HTTP route; HSTS is added only to the
  HTTPS route;
- disabled hosts are omitted; duplicate ids/domains are rejected; redirect targets are normalized;
  output order is deterministic.

The compiler does not yet emit listeners, `tls_connection_policies`, access lists or advanced
handlers. Those are later slices; the route layer stays independent so those can be added without
changing host semantics.

## `pm-config`

`assemble(&CompiledRoutes, &ConfigSettings)` wraps compiled routes in a complete Caddy
`apps.http` configuration:

- `ConfigSettings` defaults to 80/443; the ports are written to both `http_port`/`https_port` and
  the `pm_http`/`pm_https` `listen` addresses;
- HTTP routes stay on `pm_http` with `automatic_https.disable_redirects` set, so host-level
  redirects remain authoritative; HTTPS routes stay on `pm_https`;
- route order is the compiler order; the JSON is deterministic and contains no private-key
  material;
- `assemble_from_hosts` runs `compile_routes` first and reports a `ConfigError` for invalid hosts.

`assemble_with_tls(&[Host], &[AutoCertificatePolicy], &ConfigSettings)` is the policy-aware entry
point. It compiles the same routes and adds a deterministic `apps.tls`:

- `certificates.automate` is the sorted union of enabled policy subjects;
- `automation.policies[]` has one entry per enabled policy in id order, with its subjects, optional
  `key_type`/`renewal_window_ratio`, and one issuer module:
  - `letsencrypt` -> `acme` with `https://acme-v02.api.letsencrypt.org/directory`;
  - `zerossl` -> `acme` with `https://acme.zerossl.com/v2/DV90` (no EAB secret is stored in PM);
  - `internal` -> `{ "module": "internal" }` (no ACME challenge object);
  - HTTP-01/TLS-ALPN-01 set the corresponding `issuers[i].challenges` flags.
- A policy with the `dns01` challenge returns a located `ConfigError::UnsupportedDnsChallenge`
  because this slice stores no DNS provider credentials; no half-configured DNS policy is emitted.
- Domains of hosts whose TLS mode is not `Auto` (Disabled, Manual, ACME-configured or
  Internal-CA) are added to `apps.http.servers.pm_http|pm_https.automatic_https.skip` unless an
  enabled policy automates them. Skipping prevents Caddy from silently auto-issuing a second
  certificate for a name an explicit certificate or manual loader already owns.

`assemble_with_tls_and_certificates` additionally emits, when stored manual certificates exist:

- `apps.tls.certificates.load_files[]` with absolute `certificate`/`key` paths and the tag
  `pm-cert-<id>`;
- `apps.http.servers.pm_https.tls_connection_policies[]` matching the certificate's DNS names by
  SNI and selecting `any_tag: ["pm-cert-<id>"]`, followed by an empty default policy.

The original `assemble`/`assemble_from_hosts` output is unchanged: they never emit `apps.tls`.
`PmRuntime::assemble` uses the certificate-aware path, so stored intent policies and manual
certificates reach `/api/v1/config`.

This crate does **not** emit logging, access lists or perform the admin apply; applying is the
separate pipeline in `pm-runtime`. The optional integration test validates manual `load_files`/SNI
configs and assembled configs (including the TLS automation and skip shapes) with
`caddy-rs validate --adapter json` when `.scratch/rust-target/debug/caddy-rs` exists (or
`CADDY_RS_BIN` names one) and skips with a diagnostic otherwise; unit tests never require the
binary.

## Config apply

The ordered pipeline lives in the reusable core crate `caddy-rs-config-tx`
(`ConfigApplyPipeline` + `ConfigTarget`); `ConfigApplyService` in `pm-runtime` is the PM
composition of that pipeline and is the only path that changes the live caddy-rs config:

1. assemble the deterministic config from stored hosts, policies and manual certificates;
2. the core pipeline stages it in `ConfigTx`, which validates Caddy JSON structure and computes
   the hash, then compares the full config with the active generation;
3. the core pipeline captures the target's current config, `POST /load`s the staged document to a
   loopback-only caddy-rs admin listener, and verifies with `GET /config/` (the `admin` app is
   ignored because the PM does not own it);
4. on failure the core pipeline reloads the previously active generation, or the captured baseline
   on a first apply, writes a `Failed` revision to the core audit history, and returns the
   target/verification/rollback error;
5. on success the PM records an `applied` row in `config_revisions` in `pm-state` and marks
   unexpired pending manual certificates `issued`; on failure it records a `failed` row with a
   bounded error and leaves the previous generation active.

The admin URL must be a literal loopback IP (`http://127.0.0.1:2019` or `http://[::1]:2019`).
Hostnames are rejected because DNS can move them; HTTPS is not accepted by this client because
the PM does not own the admin certificate. A non-loopback URL is refused unless the caller
explicitly opts in. The client disables redirects, bounds the `/config/` response, and never
stores or returns the admin response body, config bytes, or secrets.

The API route is `POST /api/v1/config/apply` and requires `ApiState::with_applier`; without an
injected pipeline it is a typed `503`, so starting the API never applies by itself. The pipeline
holds an in-process lock, so concurrent apply requests serialize rather than race. `GET
/api/v1/config/revisions` exposes the durable history. Automatic apply after every host or
certificate mutation, with quarantine of the affected hosts, remains PM-107; this slice is the
explicit apply primitive it will call.

## `pm-hosts`

`HostRepository` persists validated `Host` documents and a normalized-domain index in one
`pm-state` store:

- `create` checks the host id and every domain index are absent, then writes the host and indexes in
  one transaction;
- `update` requires the caller's revision, checks added domains, releases removed domains and
  commits atomically;
- `delete` requires the revision, refuses an index owned by another host, and leaves a tombstone so
  the id is never reused;
- `next_id` reserves a monotonic id in the same store, skipping existing and retired ids;
- `get`, `list`, `snapshot_hosts`, `domain_owner`.

The repository validates `Host::validate_structure` before writing. It does **not** load certificate
or policy objects; the API/service layer performs the full `Host::validate` coverage check before a
mutation when TLS references are involved.

## `pm-service`

`HostService` is the command layer a future API/UI calls. It owns no storage of its own, but it
can be wired to the host repository and an optional policy repository:

- `create(HostDraft)` reserves `next_id`, builds `Host::new`, validates the TLS binding, and calls
  the repository. The id is allocated before validation, so a rejected draft, a failed TLS
  validation or a domain conflict consumes it; id gaps are normal and ids are never reused;
- `update(id, expected_revision, draft)` and `delete(id, expected_revision)` pass the caller's
  revision straight through, preserving the repository's compare-and-swap (update does not read the
  current host first). Update builds and validates the candidate host before `repository.update`,
  so a rejected update leaves the stored host and its revision unchanged;
- `list()` returns `StoredHost` values with revisions; `compile()` reads one snapshot and calls
  `compile_routes`.

`HostService::new(store)` configures no policy repository. It keeps the disabled-TLS path unchanged
(the repository still validates structure), but any `TlsMode::Auto` draft fails with
`ServiceError::PolicyValidationUnavailable` instead of silently skipping coverage.
`HostService::with_policies(store, policy_repository)` must receive a `PolicyRepository` over the
same underlying store and enables policy-aware validation before every create and update:

- `TlsMode::Disabled` loads nothing and proceeds; the repository still runs
  `Host::validate_structure`;
- `TlsMode::Auto` loads `tls.auto_policy_id`. A missing policy is a located
  `ServiceError::PolicyNotFound`; a disabled policy or a domain-coverage failure is a located
  `ServiceError::Tls` carrying the `CoreError` from `Host::validate(None, Some(&policy))`, which
  also re-checks TLS mode/reference consistency and coverage;
- `TlsMode::Manual`, `AcmeConfigured` and `InternalCa` fail with
  `ServiceError::UnsupportedExplicitCertificate`. There is no certificate repository yet, so
  coverage cannot be proven; reporting success would silently skip it.

`HostDraft` carries `domains`, `tls` and `spec`; drafts are always enabled and `update` replaces the
whole host. The repository still validates structure before writing. Failed policy-aware validation
persists nothing, but a failed `create` has already consumed its allocated id; a failed `update`
does not change the stored host or revision. This crate does **not** load certificates and does not
expose REST/UI/auth.

## `pm-policies`

`PolicyRepository` persists validated `AutoCertificatePolicy` documents in the same `pm-state`
store, one `pm.policies` document per policy:

- `create` validates the policy, rejects a duplicate or retired id, and writes the document in one
  transaction;
- `update` requires the caller's revision and commits under a compare-and-swap;
- `delete` requires the revision and writes a `pm.policy-tombstones` marker, so a policy id is never
  reused;
- `next_id` reserves a monotonic id from a counter persisted in `pm.meta`, skipping existing and
  retired ids. Arithmetic is checked, so a counter at `u64::MAX` fails with `IdExhausted` instead of
  overflowing;
- `get`, `list`, `snapshot_policies`;
- `validate_policy_coverage(policy, &[Host])` checks only hosts bound with `TlsMode::Auto` to that
  policy and reports the uncovered domains together with the affected host ids; manual/ACME/CA and
  disabled hosts are ignored.

The repository is persistence only and does not depend on `pm-hosts`; coverage reads `pm-core`
`Host` values directly.

## `pm-runtime`

`PmRuntime::open(RuntimeConfig::new(data_dir))` is the composition root. It owns the one filesystem
layout below the deployment's data directory:

```text
<data_dir>/
  pm/
    state.json   # PM host/policy documents (SnapshotStore, mode 0600)
```

PM state is **never** written directly to `<data_dir>` (`<data_dir>/state.json` is not used).

Preflight, in order:

1. reject an empty or non-directory data directory with a path-aware `RuntimeError`;
2. create a missing data directory with mode `0700` on Unix, then `<data_dir>/pm` (also `0700`);
   existing directories keep their mode and ownership — the runtime never `chown`s anything;
3. prove writability by creating a unique `.pm-write-probe-*` file **inside** `<data_dir>/pm`,
   writing it, `fsync`ing it and removing it. On failure `RuntimeError::DataDirNotWritable` names
   `<data_dir>/pm` and the I/O error and says to fix ownership/permissions. There is no fallback to
   the current directory or `/tmp`;
4. open `<data_dir>/pm/state.json` through `SnapshotStore::open`;
5. build one `HostRepository`, one `PolicyRepository`, and `HostService::with_policies` over the
   same store, exposed as `hosts()`, `policies()` and `service()`.

Both `<data_dir>` and `<data_dir>/pm` are inspected with `symlink_metadata`, never an implicitly
following `stat`. A symlink at either position is refused by default with a located
`RuntimeError::SymlinkNotAllowed` naming the link and its target. The opt-in
`RuntimeConfig::allow_symlink_data_dir(true)` canonicalises the link and requires its target to be a
directory; the canonical target becomes the effective data directory (for the root link) or the
state directory (for the `pm` link), and the normal checks then run against it. A dangling symlink
is always a located error (`SymlinkUnresolvable` with the override), is never followed, and cannot
cause recursive directory creation. `AlreadyExists` from directory creation is resolved by one
non-recursive inspection.

`status()` returns `data_dir`, `state_path`, `host_count`, `policy_count`,
`legacy_caddy_detected` and operator `warnings`. Both counts are fresh store reads on every call,
not cached.

Legacy Caddy data is detected at open from direct children of `<data_dir>`:

- directories named `certificates`, `acme` or `pki`;
- a regular file named `instance.uuid`;
- regular files named `caddy.db` or beginning with `caddy.db-`/`caddy.db.` (the SQLite database and
  its lock/journal/backup sidecars).

Detection only reads directory entries and file types (symlinks are not followed). The paths are
never opened, read, adopted, migrated or modified. A detection adds a warning to `status().warnings`
and leaves PM state under `<data_dir>/pm`; there is no automatic import from Caddy and no automatic
migration of the data directory.

`compile()` compiles the stored hosts through `pm-compiler`; `assemble(ConfigSettings)` delegates to
`pm-config`'s `assemble_from_hosts` and returns the assembled Caddy JSON. Errors are
`RuntimeError::{InvalidDataDir, NotADirectory, SymlinkNotAllowed, SymlinkUnresolvable,
SymlinkTargetNotDirectory, DataDirUnreadable, CreateDirectory, DataDirNotWritable, State, Service,
Compile, Config}` and carry the relevant path. No error contains plaintext secrets.

## `caddy-rs-pm-api`

`create_router(ApiState)` builds the `/api/v1` router with the following endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{ "status": "ok", "setup": false }`; `setup` stays false until a user store exists |
| `GET` | `/setup` | Returns `{ "configured": false }` (admin user check deferred to PM-109/CORE-PM-12) |
| `GET` | `/version` | Returns `{ "version": "<crate version>", "caddy_rs": "<caddy-rs-core VERSION>" }` |
| `GET` | `/hosts` | Paginated host summaries (`id`, `domains`, `kind`, `enabled`, `revision`, `tlsMode`); filters `enabled`, `kind`, `domain` |
| `POST` | `/hosts` | Create a native host (`201` + `Location` + strong `ETag`) |
| `GET` | `/hosts/{id}` | Full native host document; supports `If-None-Match` (`304`) |
| `PUT` | `/hosts/{id}` | Replace a host; requires a matching strong `If-Match` |
| `PATCH` | `/hosts/{id}` | Change only the supplied fields; requires `If-Match` |
| `DELETE` | `/hosts/{id}` | Delete and tombstone the id; requires `If-Match` |
| `POST` | `/hosts/{id}/enable` | Set `enabled=true`; requires `If-Match` |
| `POST` | `/hosts/{id}/disable` | Set `enabled=false`; requires `If-Match` |
| `POST` | `/certificates/intent` | Record a certificate intent (`201` + `Location` + strong `ETag`); loopback-only; DNS-01 and NPM fields are typed `400`s |
| `POST` | `/certificates/custom` | Upload a manual PEM chain + key (`201`, metadata only); loopback-only; mismatched/expired/wrong-SAN input is a located `400` |
| `GET` | `/certificates` | Paginated mixed intent/manual list with `origin` and inventory-derived `status`; filters `domain`, `status` |
| `GET` | `/certificates/{id}` | One intent or manual certificate; ambiguous shared ids are `409` |
| `GET` | `/certificates/intent/{id}` | Unambiguous intent detail |
| `GET` | `/certificates/custom/{id}` | Unambiguous manual detail (`If-None-Match` supported) |
| `DELETE` | `/certificates/custom/{id}` | Delete a manual certificate and its secret files; strong `If-Match`; refuses a referencing host |
| `GET` | `/config` | Assembled Caddy JSON (routes + TLS automation) with a weak `ETag`; honours `If-Match` and `If-None-Match` |
| `POST` | `/config/apply` | Assemble, load, verify and record the config; loopback-only; `503` without an injected pipeline or when the admin request fails |
| `GET` | `/config/revisions` | Paginated durable apply history (`applied`/`failed`, hash, timestamp, bounded error) |

### Shared infrastructure

- **`ApiState`** — owns a cloneable `PmRuntime`, an optional `Arc<dyn CertificateInventorySource>`
  and an optional `Arc<ConfigApplyService>`; `ApiState::with_inventory` and
  `ApiState::with_applier` inject them, and both default to absent.
- **Typed error envelope** — `{ "error": { "code": "NOT_FOUND|CONFLICT|PRECONDITION_FAILED|PRECONDITION_REQUIRED|FORBIDDEN|UNSUPPORTED_MEDIA_TYPE|VALIDATION|SERVICE_UNAVAILABLE|INTERNAL", "message": "...", "location": "field.path" } }` via `ApiError::into_response()`.
- **Pagination** — `limit` (default 50, max 200) and `offset` (default 0) query params; an out-of-range `limit` is clamped and the effective window is echoed in `{ "items": [...], "total": N, "limit": L, "offset": O }` via `PaginatedResponse<T>`.
- **Preconditions** — `evaluate_get_preconditions` implements RFC 9110 ordering for the config `GET`: a failing `If-Match` is `412 Precondition Failed`, a matching `If-None-Match` is `304 Not Modified`, and `*` matches any representation. Host mutations require a strong `If-Match`: missing is `428 Precondition Required`; stale, weak `W/"..."` or unparseable is `412`; `*` matches any current revision.
- **ETags** — config uses a weak `W/"<hash>"` content hash. Hosts use a strong `"h<id>-r<revision>"` tag derived from the stored revision, so the tag is both a cache validator and the CAS token. A mutation reads the host, requires `If-Match` to match that revision, and passes the same revision to `pm-service`; a CAS conflict after the read is `412`, never retried. Certificate details use a strong hash over the whole response body (`"c<id>-<hash>"`): the body includes inventory-derived status/expiry/issuer/source/renewal error, so a policy revision alone would produce a false `304` when a certificate is issued or starts failing.
- **Native schema** — request/response bodies are camelCase (`preserveHost`, `sslForced`, `autoPolicyId`) and reject unknown fields. NPM names such as `forward_host` are a typed `400`, not silently ignored; the `--compat npm` adapter will translate them.
- **Middleware** — request ID (`x-request-id`), structured logging, and a loopback-only mutation guard. The guard reads the socket peer from `ConnectInfo<SocketAddr>`; a missing peer or a non-loopback peer is `403`, and `X-Forwarded-For` is never trusted. This is a fail-closed boundary until PM auth lands, not authentication: the management port must stay unpublished and `create_router` must be served with `into_make_service_with_connect_info::<SocketAddr>()`.
- **No authentication yet** — the loopback guard is temporary; PM management auth is CORE-PM-12/PM-115 work.

### Certificate intents and status

`POST /certificates/intent` takes exactly `{ "domains": [...], "issuer": "letsencrypt" |
"zerossl" | "internal", "challenge": "http01" | "tls-alpn01" | "dns01" }` and records an eager
`AutoCertificatePolicy` through `PmRuntime::policies()`. It normalizes and validates every domain,
rejects duplicate domains, unknown/NPM fields and DNS-01 (no provider credentials in this slice),
and allocates the policy id with the repository's persisted `next_id()`; exhaustion and races are
typed `409`s. The response is `201` with `policyId`, `domains`, `issuer`, `challenge`, `status:
"pending"`, `Location: /api/v1/certificates/{id}` and a strong `"c<id>-<hash>"` ETag over that pending representation. No PEM,
private key or secret is accepted or returned.

`GET /certificates` and `/certificates/{id}` derive status from an injected
`CertificateInventorySource` (`CertificateRecord { domains, sans, issuer, expires_at_unix, source,
renewal_error }`):

| Status | Condition |
|---|---|
| `pending` | no record covers at least one subject |
| `renewal_error` | a covering record reports an error |
| `expired` | the latest covering record expired |
| `expiring_soon` | less than 30 days remain |
| `issued` | covered and not near expiry (also used when the source has no expiry) |

Coverage is per subject: one intent may be covered by several certificates (for example an exact
SAN plus a wildcard). A record without an expiry is still an issuance observation and is reported
`issued` with no `expiresAt`; it is never turned into a fabricated epoch date.

**Integration point (deliberately not implemented here).** `pm-api` has no HTTP client. The daemon
that owns the caddy-rs admin URL implements `CertificateInventorySource` over
`GET /runtime/inventory` and injects it with `ApiState::with_inventory`. The current caddy-rs
inventory payload (`crates/admin/src/inventory.rs`) exposes only `subject`, `sans`, `issuer`,
`source` and optional `not_after`: it has **no issuance-state or renewal-error field**. This slice
therefore reports `issued`/`expiring_soon`/`expired` from expiry and `pending` when no certificate
is observed; `renewal_error` is surfaced only when a future source can provide it. It never
fabricates "issued" from a `201`.

### Testing

Tests use `axum_test::TestServer` against a real `PmRuntime` backed by a temporary data directory:
- Health/setup/version return 200 with the documented shapes.
- `/hosts` paginates, clamps an oversized `limit`, and returns typed 400 errors for non-numeric or negative ones; filters apply before pagination.
- Host CRUD returns 201/`Location`/ETag, rejects duplicate domains with 409, rejects NPM field names with 400, and requires strong `If-Match` (428 missing, 412 stale/weak).
- `PATCH` preserves unnamed fields; enable/disable are set operations; delete tombstones the id; revisions are monotonic; a stale read cannot overwrite a newer write.
- `/config` returns a stable weak ETag; `If-None-Match` yields 304, a stale `If-Match` yields 412 with a typed `PRECONDITION_FAILED` body, and `*`/current tags succeed. If a stored policy/host cannot be assembled, the response is a typed `409 CONFLICT` naming the offending policy or host, not an opaque `500`.
- `If-Match` is evaluated before `If-None-Match`; malformed tags, including a non-UTF-8 header value, fail closed with 412.
- Mutation-side `require_if_match` rejects missing and stale revisions and accepts current/`*`.
- Certificate intents return 201/`Location`/ETag and persist an eager policy; DNS-01, NPM fields,
  duplicate/invalid domains and unknown issuers are typed 400s with a `location`; missing
  `ConnectInfo` and non-loopback peers are 403 before the body is parsed.
- Certificate list/detail derive pending/issued/expiring_soon/expired/renewal_error from a fake
  inventory (including split-certificate coverage and a record without expiry), filter before
  pagination, and `/config` after an intent contains `apps.tls` plus `automatic_https.skip` for an
  HTTP-only host.
- Error bodies carry `location` only when a field is at fault.

## `pm-import`

`import_proxy`, `import_redirection` and `import_dead` map NPM v2.16 host API payloads to `pm-core`
hosts without approximating unsupported settings:

- ids are checked (0 is rejected) and `domain_names` are normalized into host patterns;
- `certificate_id = 0` maps to disabled TLS; a non-zero id needs a caller-supplied
  `certificate_origins` map, builds `HostTls::for_explicit` and preserves the payload's
  `ssl_forced`/HSTS flags. TLS flags without a certificate are rejected rather than silently
  cleared the way NPM does, and an auto-generated origin cannot be selected by id;
- proxy upstreams map scheme/host/port with `preserve_host = true`; redirects map
  `forward_scheme` (`auto`/`http`/`https`), target and status through the core validator; dead hosts
  map to `DeadSpec`;
- non-empty `advanced_config`, non-empty `locations`, a non-zero `access_list_id` and stream
  payloads (`import_stream`) fail with a located error because the host model has no representation
  for them yet;
- `caching_enabled`, `block_exploits`, `http2_support`, a set `allow_websocket_upgrade` and
  `trust_forwarded_proto` produce warnings instead of errors, because the native route compiler does
  not apply them. In particular, `trust_forwarded_proto` does not apply proxy trust; trusted proxies
  must be configured explicitly. Redirection hosts warn for `block_exploits`/`http2_support` and
  dead hosts for `http2_support`.

The importer never invents a certificate origin and never drops an unsupported setting. Full
`Host::validate` certificate/policy coverage remains a caller responsibility, as with `pm-hosts`.

## Commands

```sh
cd pm
cargo fmt --all --check
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
  CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target-pm \
  cargo test --offline --workspace
```

## Acceptance testing

End-to-end acceptance is exercised by [`pm/acceptance/tpm-116-acceptance.sh`](acceptance/tpm-116-acceptance.sh),
tracked by task `T-PM-116`. It starts caddy-rs and caddy-rs-pm, creates a host through
`POST /api/v1/hosts`, installs a manual certificate through `POST
/api/v1/certificates/custom`, applies the configuration through `POST
/api/v1/config/apply`, and asserts:

- a real TLS handshake on port 443 (openssl `s_client`, certificate verified against the fixture CA);
- an HTTP→HTTPS 308 redirect from `ssl_forced: true`;
- an HTTP 200 through the proxied backend over HTTPS.

The script is idempotent: it allocates a fresh data directory, starts both processes on loopback-only
ports, records the applied revision, and cleans up everything on exit (success or failure). Required
binaries (`caddy-rs` and `caddy-rs-pm`) must be built first:

```sh
cd caddy-rs
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
  CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target-caddy \
  cargo build --offline

cd ../pm
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
  CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target-pm \
  cargo build --offline -p caddy-rs-pm-cli

./pm/acceptance/tpm-116-acceptance.sh
```

## Not in this slice

- the PM web UI and the NPM compatibility adapter;
- a real ACME/DNS-01 issuance service or certificate job API: this slice records intent and
  compiles Caddy automation, it does not request, renew or revoke certificates itself;
- DNS provider credentials and a DNS-01 policy path;
- a durable backend with a journal (redb/SQLite/Postgres);
- core on-demand TLS manager (tracked separately in
  `docs/research/DYNAMIC-CERTIFICATE-DECISIONS.md`).

The next slices are the PM web UI, the daemon-side inventory source, explicit ACME issuance jobs
and the core on-demand manager. The taxonomy and invariants are in
`docs/research/PROXY-MANAGER-CERTIFICATES.md`.

### Manual certificates

`POST /certificates/custom` takes exactly `{ "domains": [...], "certificate": "<PEM chain>",
"privateKey": "<PEM key>" }`. The service:

- parses only `CERTIFICATE` blocks in the chain and exactly one unencrypted PKCS#8/PKCS#1 key; it
  rejects encrypted/SEC1 keys, unknown labels, oversize input, malformed base64 and text outside
  blocks;
- proves key possession by signing a fixed challenge and verifies the signature against the leaf
  public key (no key bytes are compared);
- rejects expired and not-yet-valid leaves and any requested domain not covered by a SAN/CN
  (wildcards cover exactly one label);
- stores metadata in `pm-state` and writes the canonical chain/key to
  `<data_dir>/pm/secrets/manual-<id>.crt.pem` / `.key.pem` with `0600` files in a `0700`
  directory, using `O_CREAT|O_EXCL` and refusing symlinked paths;
- returns metadata only (`id`, `origin: "manual"`, `domains`, `status: "pending"`, `revision`,
  `keyType`, `fingerprintSha256`, validity); the API never returns PEM/key bytes and the state
  document contains no key material.

At-rest secrecy is filesystem permissions only; this slice does **not** encrypt the key file. An
operator who needs encryption at rest must place the data directory on an encrypted volume. The
status starts `pending`; only a verified config apply advances it to `issued`, so a stored upload
never claims to be live before `/load` succeeds. Deletion requires a strong `If-Match`, refuses a
certificate referenced by a host, and tombstones the id.
