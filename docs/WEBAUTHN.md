# WebAuthn / FIDO2 passkeys

`caddy-rs-auth` provides a **static, read-only passkey registry**: operators declare authorized
public keys in configuration (`apps.auth.passkeys`) or in a flat `authorized_passkeys` file, and the
keys are parsed and validated into an immutable `KeyRegistry`. There is no registration database,
no attestation verification, and no WebAuthn assertion handler in this build. This page documents
the config and file formats, the validation errors, the security caveats, and the exact status of
`caddy-rs setup --auth-method webauthn`.

Related: [AUTHN.md](AUTHN.md) (passwords, JWT, tokens), [TOTP.md](TOTP.md) (TOTP two-factor),
[CLI.md](CLI.md) (command reference; `caddy-rs run` is [CLI.md#run](CLI.md#run)).

## Status at a glance

| Capability | Status |
| --- | --- |
| COSE_Key (CBOR) and SPKI PEM public-key parsing | Implemented (`crates/auth/src/cose.rs`) |
| Immutable key registry from JSON config | Implemented, unit-tested |
| Immutable key registry from flat `authorized_passkeys` file | Implemented, unit-tested |
| ES256 (P-256) and EdDSA (Ed25519) keys | Supported |
| Registry wired into the server request path | **Not wired**: only the `caddy-rs-auth` crate and its tests reference `KeyRegistry`; no HTTP handler or config module consumes it |
| WebAuthn registration / attestation | **Not implemented** |
| WebAuthn assertion verification (challenge, signature, sign counter) | **Not implemented** |
| Credential persistence, revocation API, enrollment UI | **Not implemented** |
| PM API WebAuthn support | **Not used** — `pm-api` has no passkey/WebAuthn code |
| `caddy-rs setup --auth-method webauthn` | **Shell only** — the activation route is a placeholder that responds `503`; see below |

Because signature verification is not wired up, the registry is currently an allowlist **data
model**, not an authentication mechanism. Do not advertise it as working passkey login.

## Configuration: `apps.auth.passkeys`

`KeyRegistry::from_config` accepts the parsed JSON configuration value and looks for the array in
this order:

1. `apps.auth.passkeys` (the canonical path),
2. `auth.passkeys`,
3. top-level `passkeys`,
4. or the config value itself if it is already an array.

If none is found, the result is an **empty registry**, not an error: passkey auth is then simply
unavailable.

```json
{
  "apps": {
    "auth": {
      "passkeys": [
        {
          "key_id": "yubikey-5-nfc",
          "user": "admin",
          "name": "YubiKey 5 NFC",
          "tags": ["admin", "prod"],
          "transports": ["usb", "nfc"],
          "cose_key": "<base64url-encoded COSE_Key>"
        }
      ]
    }
  }
}
```

Each entry must be a JSON object:

| Field | Required | Rules |
| --- | --- | --- |
| `key_id` | yes | Non-empty string; trimmed; operator-chosen stable label (e.g. `yubikey-5-nfc`). It is **not** the WebAuthn credential ID. |
| `cose_key` / `pem` / `key` | yes (one) | String public key. `cose_key` is a base64url-encoded CBOR `COSE_Key`; `pem` is an SPKI PEM block; `key` accepts either and sniffs the form. If several are present the code uses the first match in the order `cose_key`, `pem`, `key`. |
| `user` | no | String; defaults to `"admin"`. |
| `name` | no | Human-readable label. |
| `tags` | no | Array of strings; used only for grouping/reporting. |
| `transports` | no | Array of strings, or a comma-separated string; stored verbatim (`usb`, `nfc`, `internal`, …). Values are not validated against a fixed set. |
| `added_at` | no | Integer unix timestamp (seconds); defaults to load time. |

The registry does not define a Caddy config module schema; `from_config` is a library entry point
over the raw JSON value.

## Flat file: `authorized_passkeys`

`KeyRegistry::from_file(path)` parses a whitespace-separated file. Blank lines and lines whose first
non-space character is `#` are ignored.

```text
# key_id          user   cose_key(base64url)   transports   [name]
yubikey-5-nfc     admin  <base64url COSE_Key>  usb,nfc      YubiKey5NFC
```

| Field | Required | Notes |
| --- | --- | --- |
| 1 `key_id` | yes | Non-empty token. |
| 2 `user` | yes | User the key authenticates; no default in the file format. |
| 3 `cose_key` | yes | Base64url COSE_Key (or PEM via the same `parse` sniffing). |
| 4 `transports` | no | Comma-separated list (`usb,nfc`); split on commas and trimmed. |
| 5 `name` | no | A single token — it may not contain whitespace. |

Flat files cannot express `tags`, and `added_at` is set to the load time. Duplicate `key_id`s are
rejected across the entries of one source.

## Validation errors

All failures are `RegistryError` and carry a location:

| Error | Rendered message | Location examples |
| --- | --- | --- |
| `InvalidKey { location, reason }` | `<location>: <reason>` | `apps.auth.passkeys[2].cose_key`, `authorized_passkeys.txt:3.cose_key` |
| `DuplicateKey { location, key_id }` | `<location>: duplicate key_id \`<key_id>\`` | `apps.auth.passkeys[1].key_id` |
| `Io { path, source }` | `cannot read <path>: <source>` | the file path |

Common reasons: entry is not an object; missing/empty `key_id`; missing `cose_key`/`pem`/`key`;
`tags`/`transports` not an array of strings; `added_at` not an integer; malformed base64url/CBOR;
unsupported key type (`expected EC2=2 or OKP=1`); unsupported algorithm (`expected ES256=-7 or
EdDSA=-8`); unsupported curve (`expected P-256=1 or Ed25519=6`); inconsistent `kty`/`alg`/`crv`;
missing COSE field; wrong field length; unsupported PEM/SPKI algorithm (only Ed25519 and P-256 are
accepted). A flat-file line with fewer than 3 fields reports the expected shape
`key_id user cose_key [transports] [name]`.

Known rough edge: a duplicate detected while loading a flat file still reports the JSON-style
location `apps.auth.passkeys[<i>].key_id`, because `from_entries` is shared by both sources.

## Supported keys

- **ES256** — COSE alg `-7`, key type EC2 (`2`), curve P-256 (`1`), uncompressed point.
- **EdDSA** — COSE alg `-8`, key type OKP (`1`), curve Ed25519 (`6`).
- PEM/SPKI input accepts Ed25519 or P-256 public keys only; any other algorithm is refused by name.

No private key material is read or stored — only public keys, so the registry file is safe to keep
in configuration management, but treat it as an authorization artifact (see below).

## Security caveats

- **The config/file is the trust root.** Anyone who can edit `apps.auth.passkeys` or
  `authorized_passkeys` can authorize a key, and `user` defaults to `admin` when omitted.
- **No revocation API.** Removing the entry and reloading is the only revocation; there is no
  per-credential disable, counter, or audit trail.
- **No ceremony.** There is no registration, attestation, challenge/response, signature
  verification, or sign-counter check in this build, so a declared key is not yet usable to
  authenticate. Do not treat registry membership as proof of possession.
- **No enrollment UI.** `caddy-rs setup` does not enroll a passkey yet (next section).
- **`key_id` is a label, not a credential ID** — it is operator-chosen and only needs to be unique
  within the registry.

## `caddy-rs setup --auth-method webauthn` (current limitation)

`caddy-rs setup` is a caddy-rs extension (in the stock-compatibility profile, selected with
`CADDY_RS_STOCK_COMPAT=true`, it is rejected as an unknown command). This build implements only the
**command surface and the generated activation layer** (T-SETUP-001). It does **not** implement the
activation handler (T-SETUP-002), WebAuthn/TOTP enrollment (T-SETUP-003), or the generation-scoped
`caddy-rs-pm` service (T-SETUP-004, ADR-006).

What it does:

```sh
caddy-rs setup --domain example.com --auth-method webauthn
```

- Flags: `--domain` (required), `--auth-method webauthn|totp` (default `webauthn`), `--storage`
  (default `file_system`; `file_system`, `redis`, `postgres`, `consul` accepted — validated only,
  no storage backend is wired), `--registration-timeout` (default `15m`; minimum 5m, maximum 60m),
  `--data-dir`, `--host` (repeatable), `--listen-address`, `--acme`, `--cloudflare`,
  `--cf-api-token`.
- It generates a temporary Caddyfile and validates it through the Caddyfile adapter. The global
  block sets `admin localhost:2019` and, unless ACME/Cloudflare is used, `local_certs`. Each host
  gets a site with a comment recording the selected auth method and timeout, a route
  `/_caddy-pm/activate*` whose handler is literally
  `respond "caddy-pm-rs activation layer is not running" 503`, and a fallback
  `respond "caddy-rs is running; use the activation URL" 200`.
- It mints single-use activation tokens that expire after the registration timeout. Tokens live in
  memory in this process only; persistence in `caddy-rs-pm` storage is T-SETUP-005.
- It writes the generated config under the data directory at `setup/Caddyfile` and starts
  `caddy-rs run --config <data-dir>/setup/Caddyfile --adapter caddyfile` (the `ServerBootRunner`
  seam). It does **not** spawn `caddy-rs-pm`. `--data-dir` selects only where the Caddyfile is
  written: the booted `run` receives no `--data-dir`, so the server still resolves its own data
  directory normally (the `--data-dir` propagation bug is T-SETUP-006).

What it does not do: serve a working enrollment page, register or verify a passkey, verify a TOTP
code, persist an enrolled credential, or disable the activation endpoint after enrollment. Both
`--auth-method` values currently differ only in the comment written into the generated Caddyfile.
The activation URL therefore returns `503` until the external activation layer exists.

To run a configuration manually:

```sh
caddy-rs run --config /path/to/Caddyfile --adapter caddyfile
```

See [CLI.md#run](CLI.md#run) for the `run` command and [CLI.md](CLI.md) for the rest of the CLI.
