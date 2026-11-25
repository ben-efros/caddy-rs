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

1. `CertID` must name the certificate: non-empty serial equal as a number (redundant leading zero
   octets ignored), and `issuerNameHash` / `issuerKeyHash` equal to the hashes of the leaf's issuer
   Name and the issuer's public key (CertID hash SHA-1 or SHA-256; any other hash fails closed).
2. The signature must verify over `tbsResponseData` under the issuer's key or, when the
   `responderID` names a certificate in `certs`, under that delegated responder's key — and only if
   that certificate is signed by the issuer, carries `id-kp-OCSPSigning`, and is valid now (5 minute
   skew on `notBefore`, none on `notAfter`). When no delegated certificate matches, verification
   uses the issuer key (same as Go). Algorithms: ECDSA with SHA-256/384/512, RSA PKCS#1 v1.5 with
   SHA-256/384/512 (2048-8192 bit) and Ed25519; SHA-1 based or unknown algorithms fail closed.
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
`serial_match_ignores_redundant_leading_zero_but_not_value`, `response_with_empty_serial_is_rejected`,
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

### Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, DIV-0087 (OCSP response signature): change the status
to `fixed` and replace the description with:

> caddy-rs verifies every OCSP response before caching or stapling it, matching certmagic's
> `ocsp.ParseResponse(body, issuer)`: the `BasicOCSPResponse` signature (issuer key, or a delegated
> responder certificate issued by the issuer, valid, and carrying id-kp-OCSPSigning), the full
> `CertID` (non-empty serial, issuerNameHash, issuerKeyHash) and `thisUpdate <= now + 5 min`,
> `now < nextUpdate`. The previous gap (signature never verified, an empty serial matching any
> certificate, freshness unchecked) is closed (SEC-MEDIUM D1). No divergence from stock remains
> beyond the shared residual that the delegated responder certificate's own revocation status is
> not checked. `stock_compat` has no effect. Test: `crates/tls/src/ocsp/tests.rs`.
