# ACME test fixtures

These are **test-only** self-signed certificates, generated locally for the ACME transport unit
tests in `crates/tls/src/acme/transport.rs`. They protect nothing and are trusted by no client;
the tests load them explicitly as trust roots or as the local TLS server identity.

- `localhost-cert.pem` / `localhost-key.pem`: ECDSA P-256 certificate for `DNS:localhost` and
  `IP:127.0.0.1` (not a CA), used by the loopback HTTPS transport test.
- `unrelated-cert.pem`: an unrelated self-signed certificate used to prove the transport rejects
  an untrusted server certificate.

Regenerate with the local OpenSSL binary, for example:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout localhost-key.pem -out localhost-cert.pem -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
```
