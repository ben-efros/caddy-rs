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
  2. RSA certificate keys smaller than 2048 bits are accepted by Caddy but rejected by
     aws-lc-rs, whose `validate_rsa_key` accepts only 2048..=8192 bits (larger keys are rejected
     too; only RSA-1024 was oracle-tested). Exact current error (RSA-1024 fixture,
     `load_files[0]`):
     `TLS configuration at `certificates`: private key for certificate `apps.tls.certificates.load_files[0] (certificate file <path>, key file <path>)` (DNS names: localhost): RSA-1024 private keys are not supported by this build: rustls' aws-lc-rs provider requires RSA keys between 2048 and 8192 bits`.
     The located error names the source entry, DNS names and detected modulus size; the key is
     not silently upgraded or ignored.
- Rationale: aws-lc-rs is the only rustls provider that implements
  `SignatureScheme::ECDSA_NISTP521_SHA512`, which is required to serve the P-521 certificates
  Caddy accepts. Rejecting the two remaining unsupported cases loudly (with a located error)
  is preferable to silently dropping a configured curve or substituting a different key size.
- Tracking: T-TLS-089 (test/doc gaps closed by T-TLS-090)
- Test: `crates/server/tests/http_tls.rs` (per-key-algorithm real handshakes and rejection
  messages, including the two-certificate `load_files[1]` identity test),
  `crates/tls/src/key_type.rs` (`rsa_modulus_size_is_classified_against_the_provider_range`,
  `brainpool_curve_oids_are_classified_as_unsupported`),
  `crates/tls/src/tls_server.rs` (`supported_private_key_matrix_builds_signing_keys`,
  `unsupported_private_key_types_are_classified`,
  `rsa_1024_keys_are_rejected_with_located_errors`,
  `brainpool_curve_keys_are_rejected_with_located_errors`,
  `each_supported_curve_negotiates_when_configured_alone`,
  `default_curves_prefer_mlkem_and_fall_back_to_x25519`,
  `default_provider_kx_groups_are_caddys_default_curves`,
  `secp521r1_curve_fails_closed_and_unknown_names_fail_loudly`),
  `crates/config/tests/tls_ciphers.rs` (`mlkem_curve_lands_in_the_connection_policy`,
  `caddy_accepted_but_runtime_unsupported_curves_fail_loudly`).

## T-TLS-090 follow-up — regression tests for the T-TLS-089 review

T-TLS-089 left three gaps that this task closes without changing the accepted configuration:

1. **Default curve set guard.** `default_provider_kx_groups_are_caddys_default_curves` asserts
   that `crypto_provider` installs exactly `[X25519MLKEM768, X25519, SECP256R1]` in that order,
   that P-384 is absent by default, and that an explicit `curves: ["secp384r1"]` policy installs
   only P-384. It fails if the explicit `provider.kx_groups` assignment is removed, if
   `DEFAULT_CURVES` changes, or if a provider upgrade changes the available set. The earlier
   handshake test did not catch any of those because a hybrid-capable client still connects.
2. **RSA-1024 and brainpool rejection tests.** `rsa_1024_keys_are_rejected_with_located_errors`
   covers PKCS#8 and PKCS#1 encodings with a SAN certificate and asserts the located
   `certificates` error names the `load_files[0]` entry, `DNS names: localhost` and `RSA-1024`;
   `brainpool_curve_keys_are_rejected_with_located_errors` covers SEC1 brainpoolP256r1 and
   PKCS#8 brainpoolP384r1 and asserts Caddy's `x509: unsupported elliptic curve` wording plus
   the detected curve name/OID. Both would fail if the key became accepted, panicked, or fell
   back to the provider's opaque parse error. The fixtures carry `subjectAltName=DNS:localhost`
   so the certificate is parsed and the key path is actually reached.
3. **Provider documentation.** `crates/tls/src/tls_server.rs` no longer describes the rustls
   `ring` provider or claims `x25519mlkem768` is unsupported; it documents aws-lc-rs, the four
   supported key-exchange groups and P-521 certificate-key support.

Oracle evidence for the fixtures: Caddy v2.11.9 loads and serves RSA-1024 in both encodings
(`serving initial configuration`) and rejects both brainpool fixtures with
`loading certificates: x509: unsupported elliptic curve`.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`: insert the `## DIV-0114` section above (next free
number after DIV-0113), keeping every field line.

`docs/compatibility/CONFIGURATION.md`, row
`servers.<name>.tls_connection_policies`: append this sentence to the existing row:

> `curves` accepts Caddy's names `x25519mlkem768`, `x25519`, `secp256r1` and `secp384r1` and
> emits them verbatim; `secp521r1` is a located `TLS-POLICY` error because rustls' aws-lc-rs
> provider has no P-521 key-exchange group (P-521 certificate keys are supported). `cipher_suites`
> accepts the six TLS 1.2 ECDHE AEAD suites; TLS 1.3/CBC names are located errors.

`docs/compatibility/CADDYFILE.md`, `tls` row: append this sentence:

> `tls { ciphers <name...>; curves <name...> }` emits `cipher_suites`/`curves`;
> `curves x25519mlkem768` is accepted (aws-lc-rs) while `curves secp521r1` is a located
> `TLS-POLICY` error.

Manual-certificate key-type summary for any future matrix column: RSA-2048/3072/4096, ECDSA
P-256/P-384/P-521 (SEC1 and PKCS#8) and Ed25519 accepted; RSA-1024 (and any RSA size outside
2048..=8192), Ed448, DSA, secp256k1, brainpool curves and encrypted PEM rejected loudly with a
located error naming the configured entry, its DNS names and the detected type (curve name/OID or
modulus size).
