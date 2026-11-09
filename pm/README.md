# caddy-rs proxy manager — foundation workspace

This is the first code slice of the proxy manager. It is deliberately independent of the
`caddy-rs` workspace and of the NPM compatibility adapter.

| Crate | Role |
|---|---|
| `caddy-rs-pm-state` | Backend-agnostic durable document state: snapshots, revisions, CAS transactions, one serialized writer. No SQL, C or network dependency. |
| `caddy-rs-pm-core` | Certificate domain model: explicit vs auto-generated origins, auto-certificate policies, host TLS binding and validation. |

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

## Commands

```sh
cd pm
cargo fmt --all --check
CARGO_HOME=/root/caddy-rs/.scratch/cargo-home \
  CARGO_TARGET_DIR=/root/caddy-rs/.scratch/rust-target-pm \
  cargo test --offline --workspace
```

## Not in this slice

- PM REST API, UI, NPM adapter;
- certificate service/ACME jobs;
- a durable backend with a journal (redb/SQLite/Postgres);
- core on-demand TLS manager (tracked separately in
  `docs/research/DYNAMIC-CERTIFICATE-DECISIONS.md`).

The next slices are the certificate policy API, the read-model synchronizer, and the core on-demand
manager. The taxonomy and invariants are in
`docs/research/PROXY-MANAGER-CERTIFICATES.md`.
