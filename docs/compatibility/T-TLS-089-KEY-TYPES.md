# T-TLS-089 compatibility note — TLS key types and curves

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. The
entry below is the next free number there (**DIV-0114**) and is reproduced here so the change that
introduces it ships with its compatibility rationale. Move it into the register at merge time.

## DIV-0114 — aws-lc-rs accepts P-521 certificate keys; P-521 key exchange and RSA-1024 stay rejected

- Status: accepted
- Area: TLS
- Caddy behaviour: certificate private keys may be RSA (Go accepts 1024-bit keys), ECDSA P-256,
  P-384 or P-521 (SEC1 `EC PRIVATE KEY` or PKCS#8 `PRIVATE KEY`) and Ed25519; Ed448, DSA,
  secp256k1, brainpool curves and encrypted PEM keys are rejected (`x509: unsupported elliptic
  curve`, `encrypted private keys are not supported; ...`). `tls_connection_policies[].curves`
  accepts `x25519mlkem768`, `x25519`, `secp256r1`, `secp384r1` and `secp521r1`, defaulting to
  `[x25519mlkem768, x25519, secp256r1]`.
- caddy-rs behaviour: the rustls provider is aws-lc-rs 1.19 (rustls 0.23.46). Certificate keys now
  accept RSA-2048/3072/4096 (PKCS#1 and PKCS#8), ECDSA P-256 (SEC1 and PKCS#8), P-384, P-521
  (SEC1 and PKCS#8) and Ed25519. Encrypted PEM, Ed448, DSA, secp256k1 and other curves remain
  rejected with located errors that name the source entry, DNS names, detected label/algorithm
  OID and (where Caddy rejects the same key) Caddy's wording. `curves` accepts
  `x25519mlkem768`, `x25519`, `secp256r1` and `secp384r1`; the default list is Caddy's exact
  `[x25519mlkem768, x25519, secp256r1]`. Two accept/reject differences remain because the
  provider has no implementation for them:
  1. `curves: ["secp521r1"]` is accepted by Caddy but rejected by caddy-rs with a located
     `TLS-POLICY` error. rustls' aws-lc-rs provider has no P-521 key-exchange group
     (`ALL_KX_GROUPS` contains X25519MLKEM768, SECP256R1MLKEM768, X25519, SECP256R1, SECP384R1,
     MLKEM768 and MLKEM1024 only). P-521 *certificate* keys are supported via signature schemes.
  2. RSA certificate keys smaller than 2048 bits are accepted by Caddy but rejected by aws-lc-rs
     (`failed to parse private key as RSA, ECDSA, or EdDSA`). The located error names the source
     entry and DNS names; it is not silently upgraded or ignored.
- Rationale: aws-lc-rs is the only rustls provider that implements
  `SignatureScheme::ECDSA_NISTP521_SHA512`, which is required to serve the P-521 certificates
  Caddy accepts. Rejecting the two remaining unsupported cases loudly (with a located error)
  is preferable to silently dropping a configured curve or substituting a different key size.
- Tracking: T-TLS-089
- Test: `crates/server/tests/http_tls.rs` (per-key-algorithm real handshakes and rejection
  messages, including the two-certificate `load_files[1]` identity test),
  `crates/tls/src/tls_server.rs` (`supported_private_key_matrix_builds_signing_keys`,
  `unsupported_private_key_types_are_classified`,
  `each_supported_curve_negotiates_when_configured_alone`,
  `default_curves_prefer_mlkem_and_fall_back_to_x25519`,
  `secp521r1_curve_fails_closed_and_unknown_names_fail_loudly`),
  `crates/config/tests/tls_ciphers.rs` (`mlkem_curve_lands_in_the_connection_policy`,
  `caddy_accepted_but_runtime_unsupported_curves_fail_loudly`).

## TLS configuration row

`docs/compatibility/CONFIGURATION.md`'s `apps.tls` row describes certificate loading and SNI
resolution without enumerating key types; `apps.tls.automation.policies[].key_type` (the
issuance key type) still lists p256/p384/rsa2048/rsa4096 as before. No row text needed changing
for this task beyond the register entry above; if the register or configuration matrix grows a
manual-certificate key-type column, it should say: RSA-2048/3072/4096, ECDSA P-256/P-384/P-521
(SEC1 and PKCS#8) and Ed25519 accepted; Ed448/DSA/secp256k1/brainpool/encrypted rejected loudly.
