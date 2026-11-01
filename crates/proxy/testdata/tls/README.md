# TLS upstream test fixtures

Copied from `crates/tls/testdata/acme/` (see that README for provenance and regeneration
instructions). They are **test-only** self-signed certificates: they protect nothing and are
trusted by no client; the proxy TLS tests load them explicitly as trust roots or as a local TLS
server identity.

- `localhost-cert.pem` / `localhost-key.pem`: ECDSA P-256 certificate for `DNS:localhost` and
  `IP:127.0.0.1` (CA:FALSE), used by the loopback HTTPS upstream tests.
- `unrelated-cert.pem`: a different self-signed certificate used to prove that an upstream whose
  certificate does not chain to the configured root is rejected.
