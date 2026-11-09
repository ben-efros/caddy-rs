# caddy-rs proxy manager — foundation workspace

This is the proxy-manager foundation workspace. It is deliberately independent of the
`caddy-rs` workspace and of the NPM compatibility adapter.

| Crate | Role |
|---|---|
| `caddy-rs-pm-state` | Backend-agnostic durable document state: snapshots, revisions, CAS transactions, one serialized writer. No SQL, C or network dependency. |
| `caddy-rs-pm-core` | Certificate and host domain model: certificate origins/policies, host TLS binding, proxy/redirect/dead host validation, domain uniqueness. |
| `caddy-rs-pm-compiler` | Deterministic Caddy JSON route compiler for proxy/redirect/dead hosts; emits HTTP and HTTPS route lists, HSTS and forced-SSL redirects. No listeners, TLS automation or key material. |
| `caddy-rs-pm-hosts` | Durable host repository over `pm-state`: get/list/create/update/delete with CAS revisions, atomic domain-index uniqueness, next-id reservation, and memory/snapshot backend tests. |
| `caddy-rs-pm-service` | Application service over `pm-hosts`: id-allocating create, CAS update/delete, list, and route compilation. No REST API, UI, auth or certificate policy loading. |

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

`AutoCertificatePolicy` owns subjects/wildcards, `on_demand` vs `eager` mode, issuer, key type and
renewal ratio. `HostTls` requires exactly one mode and validates subject coverage before a host is
saved. An auto-generated certificate cannot be selected by id; a manual/ACME certificate cannot be
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

`HostService` is the command layer a future API/UI calls. It owns no storage and no policy:

- `create(HostDraft)` reserves `next_id`, builds `Host::new` and calls the repository. The id is
  allocated before validation, so a rejected draft or a domain conflict consumes it; id gaps are
  normal and ids are never reused;
- `update(id, expected_revision, draft)` and `delete(id, expected_revision)` pass the caller's
  revision straight through, preserving the repository's compare-and-swap (update does not read the
  current host first);
- `list()` returns `StoredHost` values with revisions; `compile()` reads one snapshot and calls
  `compile_routes`.

`HostDraft` carries `domains`, `tls` and `spec`; drafts are always enabled and `update` replaces the
whole host. Structure validation stays in the repository. This crate does **not** load certificates
or auto policies and does not expose REST/UI/auth, so a caller using `Manual`, `AcmeConfigured`,
`InternalCa` or `Auto` TLS must load the referenced object and run `Host::validate` before a
mutation; the structural check cannot prove existence or domain coverage.

## Commands

```sh
cd pm
cargo fmt --all --check
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
  CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target-pm \
  cargo test --offline --workspace
```

## Not in this slice

- PM REST API/UI and the NPM compatibility adapter;
- the REST API/UI service;
- certificate service/ACME jobs;
- a durable backend with a journal (redb/SQLite/Postgres);
- core on-demand TLS manager (tracked separately in
  `docs/research/DYNAMIC-CERTIFICATE-DECISIONS.md`).

The next slices are the native REST API/UI, certificate policy persistence, the read-model
synchronizer, and the core on-demand manager. The taxonomy and invariants are in
`docs/research/PROXY-MANAGER-CERTIFICATES.md`.
