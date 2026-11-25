# SEC-MEDIUM-TLS compatibility note — TLS / certificate hardening (Group D)

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records, per finding, the stock Caddy v2.11.9 behaviour, what caddy-rs does, the tests that pin
it, and the exact register text for the Lead to merge. Stock source citations are from knowledge of
the upstream tree and name the Go file; they were not re-run against a Go oracle in this task.

## D1 — OCSP responses are signature-verified and freshness-checked (closes DIV-0087)

### Upstream

certmagic `ocsp.go` (`stapleOCSP`) POSTs the request to the responder from the leaf's AIA and calls
`ocsp.ParseResponse(body, issuer)` (`golang.org/x/crypto/ocsp`). `ParseResponse` verifies the
`BasicOCSPResponse` signature: directly against the issuer, or against the delegated responder
certificate shipped in `certs` after `CheckSignatureFrom(issuer)`. It also rejects a response whose
`CertID` serial does not match. certmagic then uses `NextUpdate`/`ThisUpdate` to decide freshness
and when to refresh. A response that fails any of these is never stapled.

### Previous caddy-rs behaviour (the bug)

`crates/tls/src/ocsp.rs` documented the missing signature check as DIV-0087 and accepted a response
when `response.serial == request.serial || response.serial.is_empty()` — an empty serial skipped
matching — with `let _ = now;` leaving `thisUpdate`/`nextUpdate` unchecked. The responder URL comes
from the certificate and is usually plain `http://`, so an on-path attacker or a poisoned corporate
proxy could feed a forged, stale or replayed "good" response that the server then stapled (a
revoked certificate masked from clients that trust the staple, or Must-Staple clients served a
bogus staple). The parser also rejected the two most common real-world encodings: `byName`
responder IDs (`[1]`) and `revoked` statuses (constructed `[1]`), so real responses were rejected
for the wrong reasons.

### Implemented behaviour (unconditional; no `stock_compat` switch — this is stock parity)

`verify_ocsp_response` runs before a response is cached or stapled, and before the certificate
status is judged:

1. `CertID` must name the certificate: non-empty serial equal as a two's-complement INTEGER value
   (only genuinely redundant sign-extension octets are ignored: positive `00 85` and negative `85`
   stay different numbers; a non-minimally encoded serial in a response is `Malformed`), and `issuerNameHash` / `issuerKeyHash` equal to the hashes of the leaf's issuer
   Name and the issuer's public key (CertID hash SHA-1 or SHA-256; any other hash fails closed).
2. The signature must verify over `tbsResponseData` under the issuer's key or, when the
   `responderID` names a certificate in `certs`, under that delegated responder's key — and only if
   that certificate is signed by the issuer, carries `id-kp-OCSPSigning`, and is valid now (5 minute
   skew on `notBefore`, none on `notAfter`). When no delegated certificate matches, verification
   uses the issuer key (same as Go). Algorithms: ECDSA with SHA-256/384/512, RSA PKCS#1 v1.5 with
   SHA-256/384/512 (2048-8192 bit) and Ed25519; SHA-1 based, RSA-PSS or unknown algorithms fail
   closed (see "Divergence: signature algorithms" below).
3. `thisUpdate <= now + 5 min` and, when present, `now < nextUpdate` (boundary exclusive). A
   response without `nextUpdate` is accepted when otherwise valid, as RFC 6960 allows.

Typed errors: `SerialMismatch`, `IssuerMismatch`, `SignatureInvalid`, `UnauthorizedResponder`,
`Expired`, `NotYetValid`, `Malformed` (empty serial, missing signature, truncated DER). A failed
verification leaves any previously cached staple untouched and enters the existing retry backoff.
The `stock_compat` flag is not consulted: stock Caddy is already strict, so both modes behave the
same.

Residual (not a divergence from stock): revocation of the *delegated responder certificate itself*
is not checked, nor is the responder certificate chain beyond the direct issuer signature — the same
scope as `ocsp.ParseResponse`.

### Tests

`crates/tls/src/ocsp/tests.rs` (fixtures generate a CA, leaf and delegated responder certificates
and sign responses with real ECDSA P-256 keys): `valid_response_signed_by_issuer_is_accepted`,
`valid_response_with_responder_id_by_key_is_accepted`,
`response_signed_by_an_unrelated_key_is_rejected`, `response_with_tampered_body_is_rejected`,
`response_with_corrupted_signature_is_rejected`,
`response_with_unsupported_signature_algorithm_is_rejected`,
`response_without_signature_is_rejected`,
`forged_revoked_response_is_a_signature_failure_not_a_trusted_revocation`,
`genuine_revoked_and_unknown_responses_are_never_stapled`,
`response_for_a_different_serial_is_rejected`,
`serial_match_ignores_redundant_leading_zero_but_not_value` (now: non-minimal serial is malformed), `response_with_empty_serial_is_rejected`,
`response_with_wrong_issuer_hashes_is_rejected`,
`expired_response_is_rejected_and_next_update_boundary_is_exclusive`,
`not_yet_valid_response_is_rejected_beyond_the_clock_skew`,
`response_without_next_update_is_accepted_when_otherwise_valid`,
`garbage_and_truncated_responses_are_rejected`, `delegated_responder_with_ocsp_signing_eku_is_accepted`,
`delegated_responder_without_ocsp_signing_eku_is_rejected`,
`delegated_responder_not_issued_by_the_issuer_is_rejected`,
`delegated_responder_outside_its_validity_is_rejected`,
`delegated_responder_certificate_must_match_the_response_signature`,
`verify_signature_covers_every_supported_algorithm_and_rejects_mismatches` (Ed25519, ECDSA P-384,
RSA-2048, unknown OID).

### Review round 2 additions (D1)

* **Network-reachable panic fixed.** `parse_asn1_time` sliced by byte offset after only a UTF-8
  check; a multi-byte character (producedAt `18 10 "201<e-acute>0101000000Z"`, UTCTime
  `17 0E 32 C3 A9 ...`) panicked before any signature check, from a plain-HTTP AIA responder or an
  on-path attacker (process abort with `panic=abort`, otherwise the refresh task died and stapling
  silently stopped). It now requires ASCII digits at the exact length and validates
  month/day(per month, leap years)/hour/minute/second; day 00 / month 03 no longer underflows
  `day - 1`. Other indexing in `ocsp.rs` and `acme/transport.rs` parsers was reviewed: every slice is
  guarded by an earlier length or emptiness check; truncation at every offset and single-bit flips
  of a valid response are table-tested (`every_truncation_and_bit_flip_...`).
* **Strict DER envelope.** The envelope is unsigned but stapled byte for byte. Minimal length
  encodings and no trailing bytes are now required at the OCSPResponse, `[0]`, ResponseBytes,
  OCTET STRING, BasicOCSPResponse, certs and AlgorithmIdentifier levels, so an on-path attacker can
  no longer append or re-encode a genuine response (Go's `ocsp.ParseResponse` rejects trailing
  data). Responses larger than 32 KiB are rejected: the embedded `certs` list is outside the
  signature, so without a bound an attacker could inflate a genuine staple sent to every client.
  Residual: the `certs` list contents (up to that bound) remain unauthenticated, as in Go.
* **Revocation and expiry.** A verified `revoked` response evicts the cached staple (new
  `OcspError::Revoked`; `unknown` is `UnknownStatus`), the server drops the staple from the live
  resolver entry and logs an ERROR, and `staple()` never serves a response whose `nextUpdate` has
  passed. certmagic additionally *renews* a revoked managed certificate; that re-issuance is not
  implemented here (the certificate keeps being served without a staple, and the error log says to
  replace it) - a gap to close with the renewal plumbing.
* **Independent fixtures.** `crates/tls/tests/fixtures/ocsp/` holds responses generated by the
  OpenSSL CLI (RSA-2048, P-256, P-384, Ed25519 CAs; good and revoked with reason; direct and
  delegated; byName and byKey; with and without nonce; see its README). They parse, verify and drive
  the stapler; mutation of any signed or signature byte never verifies.
* Several `SingleResponse`s: only the first is read, so a response that lists our certificate
  second fails closed (`SerialMismatch`); Go picks the matching entry. Not a security issue, may
  cost stapling against unusual responders.

### Divergence: signature algorithms (not "matches certmagic")

From the reviewer's and my own recollection of `golang.org/x/crypto/ocsp` (not re-verified against
the source in this task): Go's OCSP verifier maps the response's `signatureAlgorithm` to an
`x509.SignatureAlgorithm` and calls `Certificate.CheckSignature`, which accepts SHA-1 based
algorithms (`sha1WithRSA`, `ecdsa-with-SHA1`) and does not apply a minimum RSA key size; whether it
accepts RSA-PSS I could not establish. caddy-rs deliberately accepts only ECDSA SHA-256/384/512,
RSA PKCS#1 v1.5 SHA-256/384/512 with 2048-8192 bit keys, and Ed25519. A responder that still signs
with SHA-1 (some enterprise CAs / AD CS defaults), RSA-PSS or a sub-2048-bit RSA key therefore
loses stapling, and a Must-Staple certificate behind such a responder fails closed. No
`stock_compat` switch was added: adding SHA-1 acceptance to an already-network-reachable verifier is
a security regression the operator should opt into with a dedicated knob (follow-up). Test:
`sha1_and_pss_response_signatures_are_rejected_with_a_typed_error`.

### Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, DIV-0087 (OCSP response signature): change the status
to `fixed` and replace the description with:

> caddy-rs verifies every OCSP response before caching or stapling it, following certmagic's
> `ocsp.ParseResponse(body, issuer)` with a stricter algorithm policy: the `BasicOCSPResponse` signature (issuer key, or a delegated
> responder certificate issued by the issuer, valid, and carrying id-kp-OCSPSigning), the full
> `CertID` (non-empty serial, issuerNameHash, issuerKeyHash) and `thisUpdate <= now + 5 min`,
> `now < nextUpdate`. The previous gap (signature never verified, an empty serial matching any
> certificate, freshness unchecked) is closed (SEC-MEDIUM D1). No divergence from stock remains
> beyond the shared residual that the delegated responder certificate's own revocation status is
> not checked. Divergences: SHA-1 and RSA-PSS response signatures and RSA keys under 2048 bits are
> rejected (stock x/crypto/ocsp accepts SHA-1 RSA); the envelope must be strict DER with no
> trailing data and at most 32 KiB; a verified `revoked` response withdraws the staple but does not
> trigger re-issuance. `stock_compat` has no effect. Tests: `crates/tls/src/ocsp/tests.rs`,
> `crates/tls/src/ocsp/tests/hardening.rs`.

## D2 — client-auth modes `request` / `require` need an explicit acknowledgement

### Upstream

`modules/caddytls/connpolicy.go` (`ClientAuthentication.ConfigureTLSConfig`): `mode` `request` maps
to `tls.RequestClientCert` and `require` to `tls.RequireAnyClientCert`. Neither verifies the
presented chain against `ClientCAs`; only `verify_if_given` (`VerifyClientCertIfGiven`) and
`require_and_verify` (`RequireAndVerifyClientCert`) do. A trust pool configured next to `request`/
`require` is therefore not used for validation, and `require` without a pin accepts any
self-signed certificate. caddy-rs mirrors these semantics (`AcceptAnyClientCertVerifier`).

### Problem

The behaviour is stock, but operators read `require` as mutual TLS and a `trusted_ca_certs` next to
it as the trust anchor; the listener then authenticates nothing while the
`{http.request.tls.client.*}` placeholders look populated.

### Implemented behaviour

* Default (`stock_compat` absent or `false`): a `client_authentication` with `mode` `request` or
  `require` that has no exact-leaf pin (`trusted_leaf_certs`, `trusted_leaf_cert_file`, or
  `verifiers`) is a located configuration error at
  `tls_connection_policies[0].client_authentication.mode`, unless the caddy-rs extension
  `"insecure_accept_any_client_cert": true` is present. The error text says that the configured CA
  certificates are not used in this mode and recommends `require_and_verify`. This is deliberately
  stricter than "no CA configured": a CA pool does not make these modes verify anything.
* `insecure_accept_any_client_cert` must be a boolean; `true` with any other effective mode
  (`verify_if_given`, `require_and_verify`, or no mode) is an error (nothing to acknowledge);
  `false` is the same as absent.
* `stock_compat: true`: stock behaviour — `request`/`require` load without pin or acknowledgement,
  and the extension field is rejected with a located error (stock has no such field; extension
  fields are never silently accepted under `stock_compat`).
* An exact-leaf allowlist is a real pin and needs no acknowledgement in either mode.
* Whenever a listener is built with an unverified mode and no pinned leaf (acknowledged or
  `stock_compat`), a WARN log states that any client certificate is accepted.
* The Caddyfile adapter maps the `client_auth` subdirective `insecure_accept_any_client_cert` (no
  arguments) to the JSON field. `crates/tls` gains the `tracing` workspace dependency for the WARN.
* Handshake behaviour is unchanged: `require_and_verify` refuses a certificate that does not chain
  to the CA; acknowledged `require` accepts any certificate but still demands one.

Embedders calling `TlsServerOptions::from_connection_policies{,_with_ca_pool}` get the secure
(non-`stock_compat`) policy; `from_connection_policies_with_stock_compat` takes the flag, and the
server runtime passes the generation's `stock_compat`.

### Tests

`crates/tls/src/tls_server.rs`: `unverified_client_auth_without_pinning_is_rejected_by_default`,
`stock_compat_keeps_stock_unverified_client_auth`, `acknowledged_unverified_client_auth_is_accepted`,
`leaf_pinned_unverified_client_auth_needs_no_acknowledgement`,
`verifying_client_auth_modes_are_unaffected_and_reject_a_pointless_acknowledgement`,
`acknowledgement_field_is_validated_and_a_caddy_rs_extension`,
`require_and_verify_rejects_and_acknowledged_require_accepts_an_untrusted_cert` (real handshakes).
`crates/server/tests/http_client_auth.rs`:
`unverified_client_auth_mode_needs_acknowledgement_unless_stock_compat` (runtime threads the flag).
`crates/config/tests/upstream_adapt.rs`: `tls_client_auth_accept_any_acknowledgement_adapts_to_json`.
Existing request/require end-to-end tests (`http_client_auth.rs`, `http3.rs`) now carry the
acknowledgement.

### Exact program-repository text to merge

New `docs/compatibility/BEHAVIOR-DIVERGENCES.md` entry (`caddy-rs behaviour`, secure default, area
TLS):

> `tls_connection_policies[].client_authentication.mode` `request` and `require` accept any client
> certificate without validating its chain (stock Caddy `RequestClientCert` /
> `RequireAnyClientCert`, which also ignores a configured CA pool in these modes). caddy-rs keeps
> those semantics but, outside `stock_compat true`, refuses to load such a policy unless an exact
> leaf allowlist pins the accepted certificates or the caddy-rs extension
> `client_authentication.insecure_accept_any_client_cert: true` (Caddyfile `client_auth`
> subdirective of the same name) acknowledges the intent, and logs a WARN when the listener is
> built. `stock_compat true` restores stock acceptance without acknowledgement and rejects the
> extension field. `verify_if_given` and `require_and_verify` are unchanged. Tests:
> `crates/tls/src/tls_server.rs`, `crates/server/tests/http_client_auth.rs`.

## D3 — ACME / OCSP response bodies are bounded

### Upstream

Go's ACME client stack (acmez, used by certmagic) reads HTTP response bodies through bounded readers
and `ocsp.ParseResponse` is fed a size-limited body; neither buffers an unbounded response. Exact
upstream limits are not reproduced here.

### Previous caddy-rs behaviour

`HyperTransport::perform` (`crates/tls/src/acme/transport.rs`) did `body.collect().await.to_bytes()`
with no limit. The same transport carries OCSP fetches (`HyperOcspTransport`), CA-bundle downloads
and ACME JSON, so a hostile or compromised ACME server, an OCSP responder named by a certificate's
AIA, or an on-path proxy could make the process buffer an unbounded body (memory exhaustion).

### Implemented behaviour (unconditional, parity-neutral)

Every response body is read through `http_body_util::Limited` with
`MAX_RESPONSE_BODY_BYTES = 4 MiB`. A body of exactly the limit is accepted; one byte more (declared
by `Content-Length` or streamed chunked with no length) fails with a located
`AcmeError::Transport` ("response body exceeds the 4194304 byte limit") and the excess is never
buffered. Other body read errors keep their original message. No `stock_compat` dependency.

### Tests

`crates/tls/src/acme/transport.rs`: `response_body_at_the_cap_is_accepted`,
`response_body_one_byte_over_the_cap_is_rejected`, `unbounded_chunked_response_stops_at_the_cap`
(a local server that streams chunks until the client disconnects),
`limited_body_reader_boundaries_and_error_kinds` (limit-1/limit/limit+1 and non-limit errors).
Mutation check: raising the limit to `usize::MAX` makes the three over-cap tests fail.

### Exact program-repository text to merge

No existing DIV entry. Optional note under the TLS/ACME area of `BEHAVIOR-DIVERGENCES.md`:

> caddy-rs caps every ACME/OCSP/CA-bundle HTTP response body at 4 MiB and fails the request with a
> located transport error beyond that; stock Caddy relies on bounded readers inside acmez/certmagic.
> This is a hardening with no configuration surface and no `stock_compat` switch.

## D4 — `Debug` of stored certificates and CSRs redacts private keys

### Upstream

Not applicable: Go's `fmt` does not print `certmagic.CertificateResource.PrivateKeyPEM` unless asked,
and certmagic never logs the resource; the concern is specific to Rust's derived `Debug`.

### Previous caddy-rs behaviour

`StoredCertificate` (`crates/tls/src/storage.rs`) and `CertificateRequest`
(`crates/tls/src/acme/csr.rs`) derived `Debug`, so `{:?}` printed the PKCS#8 private key PEM. Any
`tracing` field, `unwrap()`/`expect()` message, `dbg!`, error chain, or the derived `Debug` of
`MemoryStorage` (it prints its stored values) would write the private key to logs.

### Implemented behaviour (unconditional)

Both types have a manual `Debug`, in the style of `TokenCertificateKey`, that prints
`private_key_pem: "<redacted>"` (or `"<empty>"` for token-held records with no PEM) and every other
field unchanged. Serialization, equality and storage formats are untouched.

### Tests

`crates/tls/src/storage.rs::debug_output_never_contains_private_key_material` (plain and `{:#?}`
output of `StoredCertificate` and of a populated `MemoryStorage`; token-held marker);
`crates/tls/src/acme/csr.rs::certificate_request_debug_never_contains_the_private_key`. Both failed on
the derived `Debug` and pass with the manual one.

Review round 2 extended the same redaction to every other type that derived `Debug` over a secret:
`Certificate`, `TlsAlpn01Challenge`, `MemoryAcmeStorage` (values hidden, keys listed),
`ExternalAccount` (EAB HMAC key), `CertKeyPemPair`, `PkiKeyPair`, `PkiKeyPairConfig`,
`RadarOptions`/`RadarConfig` (API token), `PasswordHash`/`Argon2idHash` (plaintext, bcrypt hash,
argon2 key) and the CLI `TokenStore` (live activation tokens; only the count is shown). One
`debug_redaction` test per type covers `{:?}` and `{:#?}`; all failed on the derived `Debug`.
Reviewed and left as is: `TlsCertificate.private_key` (rustls's `PrivateKeyDer` redacts itself),
`RefreshTokenRecord` (stores only a hash), ACME-server `Account.key` (a public JWK), HTTP-01/ALPN
challenge tokens (public by protocol), `CertKeyFilePair.key` and `AdminIdentity.key` (paths).
**Still deriving `Debug` over secret-ish data, not fixed:** `crates/cli/src/enrollment.rs::State`
(`issued_uri`, the enrolment secret URI) and `authn::MemoryUserStore` (refresh-token hashes only).

### Exact program-repository text to merge

None: no divergence from stock Caddy (internal hardening, no configuration surface).

## D5 — internal CA: root `pathlen:1` (matches stock); name constraints documented only

### Upstream

Caddy's PKI app (`modules/caddypki/certificates.go`) builds the root from smallstep's
`x509util.DefaultRootTemplate` (`isCA: true`, `maxPathLen: 1`, keyUsage `certSign`/`crlSign`) and the
intermediate from `DefaultIntermediateTemplate` (`maxPathLen: 0`). Neither template carries a
NameConstraints extension. This is stated from knowledge of the upstream tree and was not checked
against a Go oracle in this task (the repository has no stock-generated root to compare with).

### Previous caddy-rs behaviour

`crates/tls/src/internal_ca.rs` created the root with `CA:TRUE` and **no** `pathLenConstraint`
(intermediate already `pathlen:0`). A compromised or misissued intermediate could therefore sign
further sub-CAs that chain to the root without a depth limit, which stock Caddy's root forbids.

### Implemented behaviour (unconditional; makes caddy-rs match stock)

Newly generated internal roots carry `basicConstraints CA:TRUE, pathlen:1`; the intermediate keeps
`pathlen:0`; leaves are not CAs. Roots already on disk (generated by caddy-rs or Caddy) are loaded
unchanged — nothing is regenerated. `stock_compat` is irrelevant (stock has the same value).

### Name constraints: not implemented (documented)

Neither stock Caddy nor caddy-rs adds NameConstraints to the internal root/intermediate. An opt-in
`name_constraints` field on `apps.pki.certificate_authorities.<id>` would need a new core config
field, validation, runtime plumbing into the internal issuer and the extension encoder — larger than
this hardening warrants — so it is deferred. Operators who need to confine a CA to DNS subtrees can
supply their own constrained `root`/`intermediate` (`PkiKeyPair`), which caddy-rs uses as-is.

### Tests

`crates/tls/src/internal_ca.rs::root_path_len_matches_caddys_smallstep_templates` (root `pathlen:1`,
intermediate `pathlen:0`, leaf not a CA); it failed with `None` for the root before the change.

### Exact program-repository text to merge

None if the register already says the internal PKI matches stock templates. Otherwise add to the
internal-CA entry: "Newly generated internal roots carry `pathlen:1` and intermediates `pathlen:0`,
matching smallstep's default templates used by Caddy. NameConstraints are not emitted (same as stock);
an opt-in constraint is deferred (SEC-MEDIUM D5)."
