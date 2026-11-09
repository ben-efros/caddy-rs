# T-TLS-084 compatibility note — CertMagic certificate metadata parity

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records the oracle evidence and the replacement `DIV-0051` text so the change that closes the
storage-format gap ships with its compatibility rationale. Move the `DIV-0051` section into the
register at merge time.

## Oracle verification (pinned Caddy v2.11.9, certmagic v0.25.6)

The oracle binary `/root/caddy-rs/.scratch/oracle-eval-2.11.9/caddy` (v2.11.9,
`github.com/caddyserver/certmagic v0.25.6`) was run offline against its own internal CA and against
a local Pebble v2.10.1 ACME CA that advertises ARI (`renewalInfo` in the directory).

Internal issuer, `XDG_DATA_HOME=.../data`, Caddyfile `localhost:9443 { tls internal }` — the
oracle wrote `certificates/local/localhost/localhost.json` (tab indentation, no trailing newline):

```json
{
	"sans": [
		"localhost"
	],
	"issuer_data": null
}
```

ACME issuer with ARI, Pebble `VA_ALWAYS_VALID=1`, Caddyfile using
`acme_ca https://127.0.0.1:14000/dir` — the oracle wrote
`certificates/127.0.0.1-14000-dir/acme-metadata.pebble.test/acme-metadata.pebble.test.json`:

```json
{
	"sans": [
		"acme-metadata.pebble.test"
	],
	"issuer_data": {
		"url": "https://127.0.0.1:14000/certZ/6ff5c62f807e373d",
		"ca": "https://127.0.0.1:14000/dir",
		"account": "https://127.0.0.1:14000/my-account/6a6c7b104c35bf51",
		"renewal_info": {
			"suggestedWindow": {
				"start": "2027-01-07T22:24:33Z",
				"end": "2027-01-09T22:24:33Z"
			},
			"_uniqueIdentifier": "HUs42kCEEnTySLdsFZee9Zyc73E.b_XGL4B-Nz0",
			"_retryAfter": "2026-11-09T20:24:34.533380417-08:00",
			"_selectedTime": "2027-01-09T04:31:31Z"
		}
	}
}
```

Both documents were reproduced byte-for-byte by the new caddy-rs serializer, and the ACME
document is committed as the fixture used by
`crates/tls/tests/caddy_storage.rs::real_caddy_acme_metadata_round_trips_byte_for_byte`.

## Source of truth

- `certmagic/certmagic.go:401-419` — `CertificateResource`: `SANs []string
  \`json:"sans,omitempty"\``, `IssuerData json.RawMessage \`json:"issuer_data,omitempty"\``,
  `CertificatePEM`/`PrivateKeyPEM` are `json:"-"`.
- `certmagic/crypto.go:147-149` — `saveCertResource` marshals the resource with
  `json.MarshalIndent(cert, "", "\t")`.
- `certmagic/config.go:784-791` — `IssuerData` is `json.Marshal(issuedCert.Metadata)`. A nil
  `Metadata` marshals to the four bytes `null`, which is non-empty, so `omitempty` does **not**
  drop the key for the internal issuer.
- `mholt/acmez/v3@v3.1.7/acme/certificate.go:34-64` — `acme.Certificate`: `url` (no `omitempty`),
  `ca`, `account`, `renewal_info`; `ChainPEM` is `json:"-"`.
- `mholt/acmez/v3@v3.1.7/acme/ari.go:40-89` — `acme.RenewalInfo`: `suggestedWindow`
  (`start`, `end` RFC 3339), `explanationURL`, `_uniqueIdentifier`, `_retryAfter`,
  `_selectedTime` (no `omitempty` on `_selectedTime`).

## The defect T-TLS-084 fixes

The old caddy-rs serializer wrote `{"sans":[...]}` and skipped `issuer_data` when a certificate had
no issuer metadata. Rewriting a real Caddy data directory therefore dropped `"issuer_data": null`
(the internal-CA document above) or reordered the ACME object's keys alphabetically instead of in
Go struct order. Unknown fields were preserved at the top level, but the document was not
byte-compatible with CertMagic.

`serialize_certificate_metadata` now:

1. omits `sans` only when the SAN list is empty (Go `omitempty`);
2. always writes `issuer_data`, with `null` when there is no issuer metadata;
3. writes `issuer_data` in `acme.Certificate` order and nested `renewal_info` /
   `suggestedWindow` in `acme.RenewalInfo` order;
4. preserves unknown keys after the known keys at every level (top level, `issuer_data`,
   `renewal_info`, `suggestedWindow`);
5. keeps CertMagic's tab indentation and no trailing newline.

The loader is unchanged in contract: a missing `.json` or a partial document still loads with the
documented defaults (SANs from the directory name, no `issuer_data`, no `metadata_extra`), and a
rewrite re-creates the Caddy shape.

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
- Tracking: T-TLS-024 T-TLS-084
- Test: `caddy-rs/crates/tls/src/storage.rs`
  (`writes_full_certmagic_certificate_resource_and_preserves_unknown_fields`,
  `writes_null_issuer_data_for_issuers_without_metadata_like_caddy`,
  `missing_certificate_metadata_loads_documented_defaults`,
  `partial_certificate_metadata_loads_documented_defaults`,
  `certmagic_certificate_metadata_fixture_round_trips_unchanged`) and
  `caddy-rs/crates/tls/tests/caddy_storage.rs`
  (`real_caddy_acme_metadata_round_trips_byte_for_byte`, fixture
  `127.0.0.1-14000-dir/acme-metadata.pebble.test`).

## DIV-0029 — no change

`DIV-0029` is about the ACME **account** JSON body (`acme/<ca>/users/<user>/account.json`), which
remains caddy-rs's own `StoredAccount` serialisation and is outside T-TLS-084's certificate
metadata scope. Its text and status stay as they are.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`: replace the existing `## DIV-0051` section with the
`## DIV-0051` section above (keeping every field line). No `CONFIGURATION.md` or `CADDYFILE.md` row
changes are required: this is a data-layout fidelity fix, not a configuration-acceptance change.
